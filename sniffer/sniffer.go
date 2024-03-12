package sniffer

/*
#cgo CFLAGS: -g -Wall -Wextra
#include <ifaddrs.h>
#include <arpa/inet.h>
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

var (
	P_IP   = uint16(C.htons(sys.ETH_P_IP))
	P_ARP  = uint16(C.htons(sys.ETH_P_ARP))
	P_IPV6 = uint16(C.htons(sys.ETH_P_IPV6))
)

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

type IPHeader struct {
	VersionAndIHL uint8
	TypeOfService uint8
	TotalLength   uint16
	ID            uint16
	Flags         uint16
	TTL           uint8
	Protocol      uint8
	Checksum      uint16
	SrcIP         [4]byte
	DstIP         [4]byte
}

func (e *IPHeader) FromBytes(buf []byte) (uintptr, uintptr) {
	if len(buf) >= 14 {
		ptr := unsafe.Pointer(&buf[0])
		hdrlen := unsafe.Sizeof(IPHeader{})
		*e = *(*IPHeader)(ptr)

		return uintptr(ptr), uintptr(hdrlen)
	} else {
		panic("ERROR: Buffer size is not (len(buf) >= 14)")
	}
}

type EthHeader struct {
	Dhost [6]byte
	Shost [6]byte
	Proto uint16
}

func (e *EthHeader) FromBytes(buf []byte) (uintptr, uintptr) {
	if len(buf) >= 14 {
		ptr := unsafe.Pointer(&buf[0])
		hdrlen := unsafe.Sizeof(EthHeader{})
		*e = *(*EthHeader)(ptr)

		return uintptr(ptr), uintptr(hdrlen)
	} else {
		panic("ERROR: Buffer size is not (len(buf) >= 14)")
	}
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

func (c *Capture) Cap(cb func(EthHeader, uintptr, uintptr)) {
	for {
		buffer := make([]byte, 65536) // Large buffer to hold a packet
		ethhdr := EthHeader{}
		n, _, err := sys.Recvfrom(c.fd, buffer, 0)
		if err != nil {
			fmt.Println("Error receiving packet:", err)
			continue
		}
		fmt.Printf("Received a packet with %d bytes\n", n)
		sptr, size := ethhdr.FromBytes(buffer)

		cb(ethhdr, sptr, size)
	}
}

func IPBytesToString(ip [4]byte) string {
	var ret string

	for k, value := range ip {
		ret += fmt.Sprint(value)
		if k != 3 {
			ret += fmt.Sprint(".")
		} else {
			ret += fmt.Sprint("")
		}
	}

	return ret
}

func MacBytesToString(mac [6]byte) string {
	return fmt.Sprintf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
