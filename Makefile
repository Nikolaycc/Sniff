GOC = go
TESTOUT = tests

all: clean test cmd

.PHONY: clean
clean:
	rm -rfv ./tests ./sniff

.PHONY: test
test: ./tests.go
	$(GOC) build ./tests.go

.PHONY: cmd
cmd: ./cmd/sniff.go
	$(GOC) build ./cmd/sniff.go

.PHONY: alt
alt: ./alt/vs.go
	$(GOC) build ./alt/vs.go

.PHONY: hotreload
hotreload: ./hotreload.c
	gcc -o hotreload hotreload.c -ldl
