# Sniff

This project implements a basic network packet sniffer built in Go.

**Core Features**

*   Capturing raw network packets from specified network interfaces.
*   Parsing Ethernet, ARP, and IP packets.
*   Layered packet analysis using a `PacketLayer` interface.
*   Implementations for Ethernet, ARP, and IP layers.

> [!WARNING]
> This library is unfinished. Keep your expectations low.

## Installation
1. Init `go mod init github.com/your/repo`
2. Get `go get -u github.com/nikolaycc/sniff`

## Build & Run

1. Clone Repo `git clone git@github.com:Nikolaycc/Sniff.git`
2. Build `make`
3. Run (might require root/administrator privileges) `./sniff -h`
4. Run Tests (might require root/administrator privileges) `./tests`

## Usage

```go
import "github.com/nikolaycc/Sniff/sniffer"
```

## Example

```go
func handlePacket(p sniff.EthLayer, sptr, size uintptr) {
    ....
}

func main() {
    s := sniff.Capture{}
    s.CreateCap("wlp2s0")
    defer s.Destroy()

    s.Cap(handlePacket)
}
```

## Cmd

```bash
$ sudo sniff -h
    Usage of ./sniff:
        -i string
            Network Interface (default "lo")
        -l int
            Loop quantity (default 1)
        -ls
            List of Network Interface
        -o string
            Output log file
```

**Contributing**

Feel free to contribute by adding support for more protocols (TCP, UDP, ICMP, etc.), improving parsing logic, and enhancing the output format.

**Future Improvements**

*   Implement TCP, UDP, and ICMP parsing.
*   Add more sophisticated error handling.
*   Create a user-friendly output with filtering options.
*   Explore integration with packet analysis libraries like gopacket.

## Contributing

1. Fork it (<https://github.com/nikolaycc/sniff/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Nikolaycc](https://github.com/nikolaycc) - creator and maintainer
