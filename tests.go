package main

import (
	"fmt"
	sniff "github.com/nikolaycc/Sniff/sniffer"
	"unsafe"
)

func handlePacket(p sniff.EthHeader, sptr, size uintptr) {
	switch p.Proto {
	case sniff.P_IP:
		jol := *(*sniff.IPHeader)(unsafe.Pointer(sptr + size))
		fmt.Println("IPv4 packet")
		fmt.Println("DstIP: ", sniff.IPBytesToString(jol.DstIP))
		fmt.Println("SrcIP: ", sniff.IPBytesToString(jol.SrcIP))
	case sniff.P_ARP:
		fmt.Println("ARP packet")
		fmt.Println("Dst Mac Address: ", sniff.MacBytesToString(p.Dhost))
		fmt.Println("Src Mac Address: ", sniff.MacBytesToString(p.Shost))
	case sniff.P_IPV6:
		fmt.Println("IPv6 packet")
	default:
		fmt.Println("Other Protocol type:", p.Proto)
	}
}

func main() {
	s := sniff.Capture{}
	s.CreateCap("wlp2s0")
	defer s.Destroy()

	s.Cap(handlePacket)
}
