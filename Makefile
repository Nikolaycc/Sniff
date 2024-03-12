GOC = go
TESTOUT = tests

all: clean test

clean:
	rm -rfv ./tests

test: ./tests.go
	$(GOC) build ./tests.go
