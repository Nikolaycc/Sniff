package sniffer

/*
#cgo CFLAGS: -g -Wall -Wextra
#include <ifaddrs.h>
*/
import "C"

import (
	"fmt"
	"os"
	"slices"
	sys "syscall"
	"unsafe"
)

const (
	GO_ETH_P_ALL = (sys.ETH_P_ALL<<8)&0xff00 | sys.ETH_P_ALL>>8
	IFA_MAX      = 20
)

type EthHeader struct {
	dhost   [6]byte
	shost   [6]byte
	proto uint16
}

func (e *EthHeader) fromBytes(buf []byte) {
	*e = *(*EthHeader)(unsafe.Pointer(&buf[0]))
}

func fixCArray(items []string) []string {
	slices.Sort(items)

	seen := make(map[string]struct{}, len(items)) // A set-like structure
	result := []string{}

	for _, item := range items {
		if _, ok := seen[item]; !ok {
			result = append(result, item)
			seen[item] = struct{}{}
		}
	}
	return result[1:]
}

type Capture struct {
	fd int
}

func (c Capture) GetIfaces() []string {
	var ifap *C.struct_ifaddrs
	ifas := make([]string, IFA_MAX)
	if C.getifaddrs(&ifap) == -1 {
		fmt.Println("Error: getifaddrs failed")
		os.Exit(1)
	}
	defer C.freeifaddrs(ifap)

	for ptr := ifap; ptr != nil; ptr = ptr.ifa_next {
		el := C.GoString(ptr.ifa_name)
		ifas = append(ifas, el)
	}

	ifas = fixCArray(ifas)

	return ifas
}

func (c *Capture) CreateCap(ifa string) {
	fd, err := sys.Socket(sys.AF_PACKET, sys.SOCK_RAW, GO_ETH_P_ALL)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		os.Exit(1)
	}

	err = sys.SetsockoptString(fd, sys.SOL_SOCKET, sys.SO_BINDTODEVICE, ifa)
	if err != nil {
		fmt.Println("Error setting socket opts:", err)
		os.Exit(1)
	}

	c.fd = fd
}

func (c *Capture) Destroy() {
	sys.Close(c.fd)
}

func (c *Capture) Cap() {
	for {
		buffer := make([]byte, 65536) // Large buffer to hold a packet
		ethhdr := EthHeader{}
		n, _, err := sys.Recvfrom(c.fd, buffer, 0)
		if err != nil {
			fmt.Println("Error receiving packet:", err)
			continue
		}
		fmt.Printf("Received a packet with %d bytes\n", n)
		ethhdr.fromBytes(buffer)

		fmt.Printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", ethhdr.dhost[0], ethhdr.dhost[1], ethhdr.dhost[2], ethhdr.dhost[3], ethhdr.dhost[4], ethhdr.dhost[5])

		fmt.Printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", ethhdr.shost[0], ethhdr.shost[1], ethhdr.shost[2], ethhdr.shost[3], ethhdr.shost[4], ethhdr.shost[5])
		fmt.Println(ethhdr.proto)
	}
}
