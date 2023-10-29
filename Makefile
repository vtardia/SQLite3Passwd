# Package version number
PACKAGE_VERSION = 1.0

# Compiler options
CFLAGS = -Wall -Wextra -Werror -std=c17 -O3 `pkg-config openssl --cflags`
LDLIBS = `pkg-config openssl --libs` -lsqlite3 -lsl3auth
LDFLAGS = -L lib
CC = gcc
AR = ar rcs

# Installation prefix
PREFIX = /usr/local

# OS Detection
OSFLAG :=
ifeq ($(OS), Windows_NT)
OSFLAG += -D WIN32
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		OSFLAG += -D LINUX -D _GNU_SOURCE
	endif
	ifeq ($(UNAME_S),Darwin)
		OSFLAG += -D MACOS
	endif
endif

all: libsl3auth sl3passwd

prereq:
	mkdir -p obj lib bin

libsl3auth: clean prereq obj/sl3auth.o obj/crypt.o
	$(AR) lib/libsl3auth.a obj/sl3auth.o obj/crypt.o

obj/sl3auth.o: sl3auth.c
	$(CC) $(CFLAGS) -c -o $@ $(OSFLAG) $<

obj/crypt.o: crypt.c
	$(CC) $(CFLAGS) -c -o $@ $(OSFLAG) $<

sl3passwd: obj/sl3passwd.o libsl3auth
	$(CC) $(CFLAGS) obj/sl3passwd.o $(LDFLAGS) $(LDLIBS) -o bin/sl3passwd

obj/sl3passwd.o: sl3passwd.c
	$(CC) $(CFLAGS) -c -o $@ $(OSFLAG) $<

# Install/uninstall targets
install: libsl3auth
	$(eval INSTALL_BIN_DIR = $(PREFIX)/bin)
	$(eval INSTALL_LIB_DIR = $(PREFIX)/lib)
	$(eval INSTALL_INC_DIR = $(PREFIX)/include)
	if test ! -d "$(INSTALL_LIB_DIR)"; then mkdir -vp "$(INSTALL_LIB_DIR)"; fi \
	&& if test ! -d "$(INSTALL_INC_DIR)"; then mkdir -vp "$(INSTALL_INC_DIR)"; fi \
	&& if test ! -d "$(INSTALL_BIN_DIR)"; then mkdir -vp "$(INSTALL_BIN_DIR)"; fi \
	&& cp lib/libsl3auth.a "$(INSTALL_LIB_DIR)/libsl3auth-$(PACKAGE_VERSION).a" \
	&& cp sl3auth.h "$(INSTALL_INC_DIR)/sl3auth.h" \
	&& cp bin/sl3passwd "$(INSTALL_BIN_DIR)/sl3passwd" \
	&& cd $(INSTALL_LIB_DIR) \
	&& ln -s libsl3auth-$(PACKAGE_VERSION).a libsl3auth.a

uninstall:
	$(eval INSTALL_BIN_DIR = $(PREFIX)/bin)
	$(eval INSTALL_LIB_DIR = $(PREFIX)/lib)
	$(eval INSTALL_INC_DIR = $(PREFIX)/include)
	rm -fv "$(INSTALL_INC_DIR)/"sl3auth*.* \
	&& rm -fv "$(INSTALL_LIB_DIR)/"libsl3auth*.* \
	&& rm -fv "$(INSTALL_BIN_DIR)/"sl3passwd

clean:
	rm -vrf obj/** bin/** lib/**
