//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf xdp.c -- -I../headers

package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	ifaceName := os.Args[1]

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		panic(err)
	}

	defer objs.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		panic(err)
	}

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: iface.Index,
	})

	if err != nil {
		panic(err)
	}

	defer xdp.Close()
	fmt.Println("xdp stub attached!")
	time.Sleep(10000 * time.Second)
}
