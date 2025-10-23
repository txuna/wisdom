package main

import (
	"fmt"
	"net"
	"sync"
)

type Server struct {
	IP   string
	Port int
}

func main() {
	fmt.Println("start loadbalancer on 8000")
	ln, err := net.Listen("tcp4", ":8000")
	if err != nil {
		panic(err)
	}

	ss := make([]Server, 0)
	ss = append(ss, Server{
		IP:   "10.201.0.5",
		Port: 8000,
	})

	ss = append(ss, Server{
		IP:   "10.201.0.6",
		Port: 8000,
	})

	var i int = 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		index := i % 2
		go handle(conn, ss[index])

		i += 1
	}
}

func handle(clnt net.Conn, server Server) {
	// connect to server
	srv, err := net.Dial("tcp4", fmt.Sprintf("%s:%d", server.IP, server.Port))
	if err != nil {
		fmt.Println(err)
		return
	}

	wg := &sync.WaitGroup{}
	// client -> server
	wg.Go(func() {
		data := make([]byte, 4096)
		for {
			n, err := clnt.Read(data)
			if err != nil {
				break
			}

			_, err = srv.Write(data[:n])
			if err != nil {
				break
			}
		}
	})

	// server -> client
	wg.Go(func() {
		data := make([]byte, 4096)
		for {
			n, err := srv.Read(data)
			if err != nil {
				break
			}

			_, err = clnt.Write(data[:n])
			if err != nil {
				break
			}
		}
	})

	wg.Wait()
}
