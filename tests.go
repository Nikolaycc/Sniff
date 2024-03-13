package main

import (
	"fmt"
	"os"
	sniff "github.com/nikolaycc/Sniff/sniffer"
)

func handlePacket(p sniff.EthLayer, sptr, size uintptr) {
	p.Print(os.Stdout)
	sx := p.NextLayer()
	switch sx.Type() {
	case "IP":
		// ip := sx.(*sniff.IPLayer)
		sx.Print(os.Stdout)

		// HERE IP Stuff...
	case "ARP":
		// arp := sx.(*sniff.ARPLayer)
		sx.Print(os.Stdout)

		// HERE ARP Stuff...
	default:
		fmt.Println("Other Protocol type:", p.EthHdr.Proto)
	}
}

func main() {
	s := sniff.Capture{}
	s.CreateCap("wlp2s0")
	defer s.Destroy()

	s.Cap(handlePacket)
}
