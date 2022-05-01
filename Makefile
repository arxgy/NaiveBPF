CLANG = clang

INCLUDE_PATH = -I/usr/share/liburing/src/include
LIBRARY_PATH = -L/usr/lib/x86_64-linux-gnu
LIB = -luring -lrt -laio

.PHONY: clean 

clean:
	rm -f Benchmark

test:	Benchmark.c
	clang -o Benchmark $(INCLUDE_PATH) $(LIBRARY_PATH) $(LIB) $?
build: test

.DEFAULT_GOAL := build
