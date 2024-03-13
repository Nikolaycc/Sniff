# Sniff

A low-level packet sniffer for GO

## Build & Run

1. Clone Repo `git clone git@github.com:Nikolaycc/Sniff.git`:
2. Build `make`
3. Run `sudo ./sniff -h`
4. Run Tests `sudo ./tests`

## Usage

```go
import "github.com/nikolaycc/Sniff/sniffer"
```

## Example

```go
func handlePacket(p sniff.EthHeader, sptr, size uintptr) {
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

## Development

```bash
$ make
```

## Contributing

1. Fork it (<https://github.com/nikolaycc/sniff/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Nikolaycc](https://github.com/nikolaycc) - creator and maintainer
