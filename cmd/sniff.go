package main

import (
	"flag"
	"fmt"
	sniff "github.com/nikolaycc/Sniff/sniffer"
	"os"
	"slices"
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

func handlePacket(p sniff.EthLayer, sptr, size uintptr) {
	if *oFlag != "" {
		var err error
		fileds, err = os.Create(*oFlag)
		check(err)
	}

	fmt.Println(p.Type())
	p.Print(fileds)
	sx := p.NextLayer()
	switch sx.Type() {
	case "IP":
		ip := sx.(*sniff.IPLayer)
		fmt.Println(ip.Type())
		sx.Print(fileds)
	case "ARP":
		arp := sx.(*sniff.ARPLayer)
		fmt.Println(arp.Type())
		sx.Print(fileds)
	default:
		fmt.Println("Other Protocol type:", p.EthHdr.Proto)
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

	err := s.CreateCap(*ifaFlag)
	check(err)
	
	s.Capn(*lFlag, handlePacket)
}
