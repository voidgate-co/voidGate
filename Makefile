# voidGate
CC      ?= gcc
CLANG   ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
LUA_VERSION ?= 5.4
LUA_DIR ?= $(PREFIX)/share/lua/$(LUA_VERSION)

PREFIX  ?= /usr/local
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

SRC     := src
BPFDIR  := src/bpf
CFLAGS  := -O2 -g -Wall -Wextra -Wno-unused-parameter -MMD -MP \
	-I$(SRC) -I$(BPFDIR)
LDFLAGS := -lbpf -lelf -lz
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I$(SRC) -I$(BPFDIR) \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-MMD -MP \
	-isystem /usr/include/$(shell dpkg-architecture \
		-qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)

USER_OBJS := src/voidgate.o src/config.o src/policy.o src/maps.o src/ipaddr.o \
	src/ctl_server.o src/http.o src/log.o
CTL_OBJS  := src/voidgatectl.o

.PHONY: all clean install install-lua test

all: voidgate voidgatectl t/unit/policy t/unit/cidr

$(BPFDIR)/voidgate.bpf.o: $(BPFDIR)/voidgate.bpf.c $(BPFDIR)/voidgate.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(BPFDIR)/voidgate.skel.h: $(BPFDIR)/voidgate.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

src/voidgate.o src/maps.o src/policy.o: \
	$(BPFDIR)/voidgate.skel.h

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

voidgate: $(USER_OBJS)
	$(CC) $(CFLAGS) -o $@ $(USER_OBJS) $(LDFLAGS)

voidgatectl: $(CTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(CTL_OBJS)

t/unit/policy: t/unit/policy.c src/policy.c src/policy.h \
	src/log.h src/config.h src/maps.h src/ipaddr.h \
	$(BPFDIR)/voidgate.h src/config.o src/ipaddr.o src/log.o
	$(CC) $(CFLAGS) -DVG_CTRL_TEST -MF t/unit/policy.d -o $@ \
		t/unit/policy.c src/policy.c src/config.o src/ipaddr.o \
		src/log.o

t/unit/cidr: t/unit/cidr.c src/config.o src/ipaddr.o src/log.o
	$(CC) $(CFLAGS) -MF t/unit/cidr.d -o $@ t/unit/cidr.c src/config.o \
		src/ipaddr.o src/log.o

# Unit tests, then XDP verdicts: real daemon + t/*.t (needs root).
test: all
	./t/unit/policy
	./t/unit/cidr
	sudo t/bin/run

clean:
	rm -f voidgate voidgatectl t/unit/policy t/unit/cidr t/unit/*.d \
		src/*.o src/*.d \
		$(BPFDIR)/voidgate.bpf.o $(BPFDIR)/voidgate.bpf.d \
		$(BPFDIR)/voidgate.skel.h

-include $(USER_OBJS:.o=.d) $(CTL_OBJS:.o=.d) t/unit/policy.d t/unit/cidr.d \
	 $(BPFDIR)/voidgate.bpf.d

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 voidgate voidgatectl $(DESTDIR)$(PREFIX)/sbin/
	install -d $(DESTDIR)/etc/voidgate
	install -m 0644 configs/voidgate.conf $(DESTDIR)/etc/voidgate/voidgate.conf
	install -d $(DESTDIR)/lib/systemd/system
	install -m 0644 systemd/voidgate.service \
		$(DESTDIR)/lib/systemd/system/voidgate.service

install-lua:
	install -d $(DESTDIR)$(LUA_DIR)
	install -m 0644 lua/voidgate.lua $(DESTDIR)$(LUA_DIR)/voidgate.lua
