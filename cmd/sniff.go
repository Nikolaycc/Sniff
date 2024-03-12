package main

import (
	"flag"
	"fmt"
	sniff "github.com/nikolaycc/Sniff/sniffer"
	"os"
	"slices"
	"unsafe"
)

var (
	oFlag  = flag.String("o", "", "Output log file")
	fileds = os.Stdout
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func handlePacket(p sniff.EthHeader, sptr, size uintptr) {
	if *oFlag != "" {
		var err error
		fileds, err = os.Create(*oFlag)
		check(err)
	}

	switch p.Proto {
	case sniff.P_IP:
		jol := *(*sniff.IPHeader)(unsafe.Pointer(sptr + size))
		fmt.Fprintln(fileds, "IPv4 packet")
		fmt.Fprintln(fileds, "DstIP: ", sniff.IPBytesToString(jol.DstIP))
		fmt.Fprintln(fileds, "SrcIP: ", sniff.IPBytesToString(jol.SrcIP))
	case sniff.P_ARP:
		fmt.Fprintln(fileds, "ARP packet")
		fmt.Fprintln(fileds, "Dst Mac Address: ", sniff.MacBytesToString(p.Dhost))
		fmt.Fprintln(fileds, "Src Mac Address: ", sniff.MacBytesToString(p.Shost))
	case sniff.P_IPV6:
		fmt.Fprintln(fileds, "IPv6 packet")
	default:
		fmt.Fprintln(fileds, "Other Protocol type:", p.Proto)
	}
}

func main() {
	s := sniff.Capture{}
	defer s.Destroy()

	ifas := s.GetIfaces()

	lsFlag := flag.Bool("ls", false, "List of Network Interface")

	lFlag := flag.Int("l", 1, "Loop quantity")
	ifaFlag := flag.String("i", "lo", "Network Interface")

	flag.Parse()

	if *lsFlag == true {
		fmt.Println("List Network Interface:")
		for idx, val := range ifas {
			fmt.Println("\t", idx+1, "->", val)
		}
		os.Exit(0)
	}

	if !slices.Contains(ifas, *ifaFlag) {
		panic("ERROR: Not found Interface")
	}
	defer fileds.Close()

	s.CreateCap(*ifaFlag)
	s.Capn(*lFlag, handlePacket)
}
