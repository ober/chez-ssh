CC = gcc
CFLAGS = -shared -fPIC -O2 -Wall -Wextra
LIBS = -lcrypto -lpthread
SCHEME = scheme

.PHONY: all clean test

all: chez_ssh_shim.so

chez_ssh_shim.so: chez_ssh_shim.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

test: chez_ssh_shim.so
	LD_LIBRARY_PATH=. $(SCHEME) --libdirs src --script tests/ssh-test.ss

clean:
	rm -f chez_ssh_shim.so
