package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Router struct {
	serverList []*Server
	objs       bpfObjects
	rd         *ringbuf.Reader
	xdpProgram link.Link
	iface      *net.Interface
}

func NewRouter(ifaceName string) (*Router, error) {
	router := &Router{
		objs: bpfObjects{},
	}

	if err := loadBpfObjects(&router.objs, nil); err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	router.iface = iface

	router.xdpProgram, err = link.AttachXDP(link.XDPOptions{
		Program:   router.objs.XdpMain,
		Interface: router.iface.Index,
	})

	if err != nil {
		router.Close()
		return nil, err
	}

	router.serverList, err = initServers()
	if err != nil {
		router.Close()
		return nil, err
	}

	if err := router.UpdateServer(router.serverList); err != nil {
		router.Close()
		return nil, err
	}

	return router, nil
}

func (r *Router) UpdateServer(servers []*Server) error {
	for i, server := range servers {
		var key uint32 = uint32(i)
		if err := r.objs.Servers.Put(&key, &bpfServerConfig{
			Ip:   server.IP,
			Mac:  [6]uint8(server.Mac),
			Port: server.Port,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (r *Router) Metric() error {
	ticker := time.NewTicker(1 * time.Second)
	for t := range ticker.C {
		fmt.Printf("===============[session map]===============\n")

		sessionMap, err := r.objs.SessionMap.Clone()
		if err != nil {
			return err
		}

		var port uint32
		var session bpfSession
		var used int = 0
		iter := sessionMap.Iterate()

		for {
			if !iter.Next(&port, &session) {
				break
			}

			if session.Used == 1 {
				used += 1
			}
		}

		sessionMap.Close()
		fmt.Printf("[%s] used: %d\n", t, used)

		used = 0
	}

	return nil
}

func (r *Router) Ring() error {

	var err error
	r.rd, err = ringbuf.NewReader(r.objs.Events)
	if err != nil {
		return err
	}

	log.Println("waiting for events...")
	var event bpfEvent
	for {
		record, err := r.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}

			log.Printf("reading from reader: %s\n", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s\n", err)
			continue
		}

		log.Printf("(%s:%d) -> (%s:%d)\n",
			IPv4NToString(event.SrcIp),
			Ntohs(event.SrcPort),
			IPv4NToString(event.DstIp),
			Ntohs(event.DstPort))

	}
	return nil
}

func (r *Router) Close() {
	r.objs.Close()
	if r.xdpProgram != nil {
		r.xdpProgram.Close()
	}

	if r.rd != nil {
		r.rd.Close()
	}
}

func IPv4NToString(n uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)
	return net.IP(b[:]).String()
}

func IPv4HToString(n uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], n)
	return net.IP(b[:]).String()
}

func Ntohs(p uint16) uint16 {
	return (p >> 8) | (p << 8)
}
