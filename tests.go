package main

import (
	"github.com/nikolaycc/Sniff/sniffer"
)

func main() {
	s := sniffer.Capture{}
	s.CreateCap("wlp2s0")
	s.Cap()
}
