GOC = go
TESTOUT = tests

all: clean test

clean: ./tests
	rm -rfv ./tests

test: ./tests.go
	$(GOC) build ./tests.go -o $(TESTOUT)
