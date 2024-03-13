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

type PacketLayer interface {
	Type() string
	Payload() []byte
	NextLayer() PacketLayer
	FromBytes(buf []byte) (uintptr, uintptr)
	Print(fd *os.File)
}

type ARPHeader struct {
	HardwareType          uint16
	ProtocolType          uint16
	HardwareAddressLength uint8
	ProtocolAddressLength uint8
	Operation             uint16
	SenderHardwareAddress [6]byte
	SenderIP              [4]byte
	TargetHardwareAddress [6]byte
	TargetIP              [4]byte
}

type ARPLayer struct {
	ARPHdr ARPHeader
}

func (al *ARPLayer) Print(fd *os.File) {
	fmt.Fprintln(fd, "ARP Layer:")

	// Hardware and Protocol Types
	fmt.Fprintf(fd, "  Hardware Type: %d ", al.ARPHdr.HardwareType)
	if al.ARPHdr.HardwareType == 1 {
		fmt.Fprintln(fd, "(Ethernet)")
	} else {
		fmt.Fprintln(fd, "(Unknown)")
	}

	fmt.Fprintf(fd, "  Protocol Type: 0x%04x ", al.ARPHdr.ProtocolType)
	if al.ARPHdr.ProtocolType == 0x0800 {
		fmt.Fprintln(fd, "(IPv4)")
	} else {
		fmt.Fprintln(fd, "(Unknown)")
	}

	// Operation
	fmt.Fprintf(fd, "  Operation: %d ", al.ARPHdr.Operation)
	if al.ARPHdr.Operation == 1 {
		fmt.Fprintln(fd, "(ARP Request)")
	} else if al.ARPHdr.Operation == 2 {
		fmt.Fprintln(fd, "(ARP Reply)")
	} else {
		fmt.Fprintln(fd, "(Unknown)")
	}

	// Sender Information
	fmt.Fprintf(fd, "  Sender MAC: %s\n", MacBytesToString(al.ARPHdr.SenderHardwareAddress))
	fmt.Fprintf(fd, "  Sender IP: %s\n", IPBytesToString(al.ARPHdr.SenderIP))

	// Target Information
	fmt.Fprintf(fd, "  Target MAC: %s\n", MacBytesToString(al.ARPHdr.TargetHardwareAddress))
	fmt.Fprintf(fd, "  Target IP: %s\n", IPBytesToString(al.ARPHdr.TargetIP))
}

func (il *ARPLayer) Type() string {
	return "ARP"
}

func (il *ARPLayer) Payload() []byte {
	return nil
}

func (il *ARPLayer) NextLayer() PacketLayer {
	// Logic to determine the next layer based on il.ipHeader.Protocol
	// Examples:
	// ... Add more cases for other protocols
	return nil
}

func (e *ARPLayer) FromBytes(buf []byte) (uintptr, uintptr) {
	if len(buf) >= 14 {
		ptr := unsafe.Pointer(&buf[0])
		hdrlen := unsafe.Sizeof(ARPHeader{})
		e.ARPHdr = *(*ARPHeader)(ptr)

		return uintptr(ptr), uintptr(hdrlen)
	} else {
		panic("ERROR: Buffer size is not (len(buf) >= 14)")
	}
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

type IPLayer struct {
	IPHdr   IPHeader
	payload []byte
}

func (il *IPLayer) Type() string {
	return "IP"
}

func (il *IPLayer) Payload() []byte {
	return il.payload
}

func (il *IPLayer) NextLayer() PacketLayer {
	// Logic to determine the next layer based on il.ipHeader.Protocol
	// Examples:
	// ... Add more cases for other protocols
	return nil
}

func (e *IPLayer) FromBytes(buf []byte) (uintptr, uintptr) {
	if len(buf) >= 14 {
		ptr := unsafe.Pointer(&buf[0])
		hdrlen := unsafe.Sizeof(IPHeader{})
		e.IPHdr = *(*IPHeader)(ptr)

		return uintptr(ptr), uintptr(hdrlen)
	} else {
		panic("ERROR: Buffer size is not (len(buf) >= 14)")
	}
}

func (il *IPLayer) Print(fd *os.File) {
	fmt.Fprintln(fd, "IP Layer:")
	fmt.Fprintf(fd, "  Source IP: %s\n", IPBytesToString(il.IPHdr.SrcIP))
	fmt.Fprintf(fd, "  Destination IP: %s\n", IPBytesToString(il.IPHdr.DstIP))
	fmt.Fprintf(fd, "  Protocol: %d\n", il.IPHdr.Protocol)
}

type EthHeader struct {
	Dhost [6]byte
	Shost [6]byte
	Proto uint16
}

type EthLayer struct {
	EthHdr  EthHeader
	payload []byte
}

func (el *EthLayer) Type() string {
	return "Ethernet"
}

func (el *EthLayer) Payload() []byte {
	return el.payload
}

func (el *EthLayer) NextLayer() PacketLayer {
	// Logic to determine the next layer based on ethHeader.Proto
	// For example, if P_IP, return an IP layer implementation
	switch el.EthHdr.Proto {
	case P_IP:
		return &IPLayer{IPHdr: *(*IPHeader)(unsafe.Pointer(&el.payload[0])), payload: el.payload[unsafe.Sizeof(IPHeader{}):]}
	case P_ARP:
		return &ARPLayer{ARPHdr: *(*ARPHeader)(unsafe.Pointer(&el.payload[0]))}
	default:
		return nil
	}
}

func (e *EthLayer) FromBytes(buf []byte) (uintptr, uintptr) {
	if len(buf) >= 14 {
		ptr := unsafe.Pointer(&buf[0])
		hdrlen := unsafe.Sizeof(EthHeader{})
		e.EthHdr = *(*EthHeader)(ptr)
		e.payload = buf[14:]

		return uintptr(ptr), uintptr(hdrlen)
	} else {
		panic("ERROR: Buffer size is not (len(buf) >= 14)")
	}
}

func (el *EthLayer) Print(fd *os.File) {
	fmt.Fprintln(fd, "Ethernet Layer:")
	fmt.Fprintf(fd, "  Source MAC: %s\n", MacBytesToString(el.EthHdr.Shost))
	fmt.Fprintf(fd, "  Destination MAC: %s\n", MacBytesToString(el.EthHdr.Dhost))
	fmt.Fprintf(fd, "  Protocol: 0x%04x\n", el.EthHdr.Proto)
}

type Capture struct {
	Fd int
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

	c.Fd = fd
}

func (c *Capture) Destroy() {
	sys.Close(c.Fd)
}

func (c *Capture) Capn(loop int, cb func(EthLayer, uintptr, uintptr)) {
	for range loop {
		buffer := make([]byte, 65536) // Large buffer to hold a packet
		ethhdr := EthLayer{}
		n, _, err := sys.Recvfrom(c.Fd, buffer, 0)
		if err != nil {
			fmt.Println("Error receiving packet:", err)
			continue
		}
		fmt.Printf("Received a packet with %d bytes\n", n)
		sptr, size := ethhdr.FromBytes(buffer)

		cb(ethhdr, sptr, size)
	}
}

func (c *Capture) Cap(cb func(EthLayer, uintptr, uintptr)) {
	for {
		buffer := make([]byte, 65536) // Large buffer to hold a packet
		ethhdr := EthLayer{}
		n, _, err := sys.Recvfrom(c.Fd, buffer, 0)
		if err != nil {
			fmt.Println("Error receiving packet:", err)
			continue
		}
		fmt.Printf("Received a packet with %d bytes\n", n)
		sptr, size := ethhdr.FromBytes(buffer)

		cb(ethhdr, sptr, size)
	}
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
