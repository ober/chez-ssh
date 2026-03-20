CC = gcc
CFLAGS = -shared -fPIC -O2 -Wall -Wextra
LIBS = -lcrypto -lpthread
SCHEME = scheme

.PHONY: all clean test test-wire test-crypto test-integration

all: chez_ssh_shim.so chez_ssh_crypto.so

chez_ssh_shim.so: chez_ssh_shim.c bcrypt_pbkdf.c bcrypt_pbkdf.h
	$(CC) $(CFLAGS) -o $@ chez_ssh_shim.c bcrypt_pbkdf.c $(LIBS)

chez_ssh_crypto.so: chez_ssh_crypto.c chez_ssh_crypto.h
	$(CC) $(CFLAGS) -o $@ chez_ssh_crypto.c $(LIBS)

test: chez_ssh_shim.so
	LD_LIBRARY_PATH=. $(SCHEME) --libdirs src --script tests/ssh-test.ss

test-wire: chez_ssh_crypto.so
	LD_LIBRARY_PATH=. $(SCHEME) --libdirs src --script tests/wire-test.ss

test-crypto: chez_ssh_crypto.so
	LD_LIBRARY_PATH=. $(SCHEME) --libdirs src --script tests/crypto-test.ss

test-integration: chez_ssh_shim.so chez_ssh_crypto.so
	LD_LIBRARY_PATH=. $(SCHEME) --libdirs src --script tests/integration-test.ss

test-all: test test-wire test-crypto

clean:
	rm -f chez_ssh_shim.so chez_ssh_crypto.so
	rm -f src/ssh/*.so src/ssh/*.wpo src/*.so src/*.wpo
