CC = gcc
SCHEME = scheme

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  SHARED_FLAG = -dynamiclib
  SO_EXT = .dylib
  LD_VAR = DYLD_LIBRARY_PATH
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl)
  CFLAGS_EXTRA = -I$(OPENSSL_PREFIX)/include
  LDFLAGS_EXTRA = -L$(OPENSSL_PREFIX)/lib
else
  SHARED_FLAG = -shared
  SO_EXT = .so
  LD_VAR = LD_LIBRARY_PATH
  CFLAGS_EXTRA =
  LDFLAGS_EXTRA =
endif

CFLAGS = $(SHARED_FLAG) -fPIC -O2 -Wall -Wextra $(CFLAGS_EXTRA) $(LDFLAGS_EXTRA)
LIBS = -lcrypto -lpthread

.PHONY: all clean test test-wire test-crypto test-integration

all: chez_ssh_shim$(SO_EXT) chez_ssh_crypto$(SO_EXT)

chez_ssh_shim$(SO_EXT): chez_ssh_shim.c bcrypt_pbkdf.c bcrypt_pbkdf.h
	$(CC) $(CFLAGS) -o $@ chez_ssh_shim.c bcrypt_pbkdf.c $(LIBS)

chez_ssh_crypto$(SO_EXT): chez_ssh_crypto.c chez_ssh_crypto.h
	$(CC) $(CFLAGS) -o $@ chez_ssh_crypto.c $(LIBS)

test: chez_ssh_shim$(SO_EXT)
	$(LD_VAR)=. $(SCHEME) --libdirs src --script tests/ssh-test.ss

test-wire: chez_ssh_crypto$(SO_EXT)
	$(LD_VAR)=. $(SCHEME) --libdirs src --script tests/wire-test.ss

test-crypto: chez_ssh_crypto$(SO_EXT)
	$(LD_VAR)=. $(SCHEME) --libdirs src --script tests/crypto-test.ss

test-integration: chez_ssh_shim$(SO_EXT) chez_ssh_crypto$(SO_EXT)
	$(LD_VAR)=. $(SCHEME) --libdirs src --script tests/integration-test.ss

test-all: test test-wire test-crypto

clean:
	rm -f chez_ssh_shim.so chez_ssh_shim.dylib chez_ssh_crypto.so chez_ssh_crypto.dylib
	rm -f src/ssh/*.so src/ssh/*.wpo src/*.so src/*.wpo
