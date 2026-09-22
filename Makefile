# voidGate
CC      ?= gcc
CLANG   ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
LUA     ?= lua
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
TEST_OBJS := tests/test_xdp.o src/ipaddr.o src/config.o src/log.o

.PHONY: all clean install install-lua test test-lua

all: voidgate voidgatectl tests/test_xdp tests/test_policy

$(BPFDIR)/voidgate.bpf.o: $(BPFDIR)/voidgate.bpf.c $(BPFDIR)/voidgate.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(BPFDIR)/voidgate.skel.h: $(BPFDIR)/voidgate.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

src/voidgate.o src/maps.o src/policy.o tests/test_xdp.o: \
	$(BPFDIR)/voidgate.skel.h

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -c $< -o $@

voidgate: $(USER_OBJS)
	$(CC) $(CFLAGS) -o $@ $(USER_OBJS) $(LDFLAGS)

voidgatectl: $(CTL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(CTL_OBJS)

tests/test_xdp: tests/test_xdp.o src/ipaddr.o src/config.o src/log.o
	$(CC) $(CFLAGS) -o $@ tests/test_xdp.o src/ipaddr.o src/config.o \
		src/log.o $(LDFLAGS)

tests/test_policy: tests/test_policy.c src/policy.c src/policy.h \
	src/log.h src/config.h src/maps.h src/ipaddr.h \
	$(BPFDIR)/voidgate.h src/config.o src/ipaddr.o src/log.o
	$(CC) $(CFLAGS) -DVG_CTRL_TEST -MF tests/test_policy.d -o $@ \
		tests/test_policy.c src/policy.c src/config.o src/ipaddr.o \
		src/log.o

test-lua: voidgate
	sudo python3 tests/test_lua.py "$(LUA)" ./voidgate

test: voidgatectl tests/test_xdp tests/test_policy test-lua
	./tests/test_policy
	sudo ./tests/test_xdp
	sudo tests/test_netns.sh

clean:
	rm -f voidgate voidgatectl tests/test_xdp tests/test_policy \
		src/*.o src/*.d tests/*.o tests/*.d \
		$(BPFDIR)/voidgate.bpf.o $(BPFDIR)/voidgate.bpf.d \
		$(BPFDIR)/voidgate.skel.h

-include $(USER_OBJS:.o=.d) $(CTL_OBJS:.o=.d) tests/test_xdp.d \
	tests/test_policy.d $(BPFDIR)/voidgate.bpf.d

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
