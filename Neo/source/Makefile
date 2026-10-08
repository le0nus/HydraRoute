PROJECT = hrneo
VERSION = 3.21.0-1

CC_MIPSEL   = mipsel-linux-muslsf-gcc
CC_MIPS     = mips-linux-muslsf-gcc
CC_AARCH64  = aarch64-linux-musl-gcc
CC_NATIVE   = gcc

COMMON_CFLAGS = -Os -Wall -Wextra -Wno-unused-parameter \
                -ffunction-sections -fdata-sections \
                -fno-unwind-tables -fno-asynchronous-unwind-tables \
                -fomit-frame-pointer \
                -fno-strict-aliasing \
                -DVERSION=\"$(VERSION)\" \
                -Iinclude

COMMON_LDFLAGS = -Wl,--gc-sections -Wl,--build-id=sha1 -s

CFLAGS_MIPSEL  = $(COMMON_CFLAGS) -march=mips32r2 -mtune=1004kc -EL -msoft-float \
                 -mno-check-zero-division -mno-shared -mno-plt
CFLAGS_MIPS    = $(COMMON_CFLAGS) -march=mips32r2 -mtune=1004kc -msoft-float \
                 -mno-check-zero-division -mno-shared -mno-plt
CFLAGS_AARCH64 = $(COMMON_CFLAGS) -march=armv8-a \
                 -mno-outline-atomics -fno-exceptions
CFLAGS_NATIVE  = $(COMMON_CFLAGS)

LDFLAGS_STATIC  = $(COMMON_LDFLAGS) -static -static-libgcc
LDFLAGS_MIPS    = $(LDFLAGS_STATIC) -no-pie
LDFLAGS_AARCH64 = $(LDFLAGS_STATIC) -no-pie -Wl,-z,norelro
LDFLAGS_DYNAMIC = $(COMMON_LDFLAGS)

LIBS =

SRCS = src/main.c src/util.c src/log.c src/config.c src/args.c src/params.c src/watchlist.c src/ipset_nl.c src/ipset_start.c src/dns.c src/packet_capture.c src/iptables.c src/guard.c src/guard_status.c src/rtnl.c src/guard_monitor.c src/signal_handler.c src/commit_sched.c src/rci.c src/conntrack.c src/geodat.c src/routing.c src/probe_tls.c src/probe_http.c src/probe_quic.c src/quic_crypto.c src/bogon.c src/nflog_capture.c src/l7_dispatch.c src/l7_firewall.c src/tcp_reasm.c src/watchlist_api.c

.PHONY: all clean mipsel mips aarch64 native check

all: mipsel mips aarch64

mipsel: CC = $(CC_MIPSEL)
mipsel: CFLAGS = $(CFLAGS_MIPSEL)
mipsel: LDFLAGS = $(LDFLAGS_MIPS)
mipsel: build/$(PROJECT)-mipsel

mips: CC = $(CC_MIPS)
mips: CFLAGS = $(CFLAGS_MIPS)
mips: LDFLAGS = $(LDFLAGS_MIPS)
mips: build/$(PROJECT)-mips

aarch64: CC = $(CC_AARCH64)
aarch64: CFLAGS = $(CFLAGS_AARCH64)
aarch64: LDFLAGS = $(LDFLAGS_AARCH64)
aarch64: build/$(PROJECT)-aarch64

native: CC = $(CC_NATIVE)
native: CFLAGS = $(CFLAGS_NATIVE)
native: LDFLAGS = $(LDFLAGS_DYNAMIC)
native: build/$(PROJECT)

build/$(PROJECT): $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

build/$(PROJECT)-mipsel: $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

build/$(PROJECT)-mips: $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

build/$(PROJECT)-aarch64: $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

check:
	@mkdir -p build
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_commit_sched.c src/commit_sched.c -o build/check_commit_sched
	./build/check_commit_sched
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_guard.c src/guard.c -o build/check_guard
	./build/check_guard
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_signal_timer.c src/signal_handler.c src/log.c src/util.c -o build/check_signal_timer
	./build/check_signal_timer
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_nf.c src/l7_firewall.c src/util.c src/log.c -o build/check_nf
	./build/check_nf
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=run_command_output,--wrap=run_command_stdin,--wrap=log_write,--wrap=l7_firewall_load_kmod_if_present,--wrap=proc_list_has tests/check_connmark.c src/iptables.c src/guard.c src/guard_status.c src/l7_firewall.c src/util.c src/log.c -o build/check_connmark
	./build/check_connmark
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=run_command_output,--wrap=run_command_stdin,--wrap=log_write,--wrap=l7_firewall_load_kmod_if_present,--wrap=proc_list_has tests/check_raw_modules.c src/iptables.c src/guard.c src/guard_status.c src/l7_firewall.c src/util.c src/log.c -o build/check_raw_modules
	./build/check_raw_modules
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=run_command_output,--wrap=run_command_stdin,--wrap=log_write,--wrap=l7_firewall_load_kmod_if_present,--wrap=proc_list_has tests/check_raw_start.c src/iptables.c src/guard.c src/guard_status.c src/l7_firewall.c src/util.c src/log.c -o build/check_raw_start
	./build/check_raw_start
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=run_command_output,--wrap=run_command_stdin,--wrap=log_write,--wrap=l7_firewall_load_kmod_if_present,--wrap=proc_list_has,--wrap=socket,--wrap=bind,--wrap=setsockopt,--wrap=connect,--wrap=send,--wrap=recv,--wrap=close tests/check_recheck.c src/iptables.c src/guard.c src/guard_status.c src/l7_firewall.c src/rtnl.c src/rci.c src/config.c src/params.c src/util.c src/log.c -o build/check_recheck
	./build/check_recheck
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=log_write,--wrap=fwrite,--wrap=fclose,--wrap=rename,--wrap=calloc tests/check_guard_status.c src/guard_status.c src/log.c src/util.c -o build/check_guard_status
	./build/check_guard_status
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=socket,--wrap=bind,--wrap=setsockopt,--wrap=send,--wrap=recv,--wrap=close,--wrap=clock_gettime tests/check_rtnl.c src/rtnl.c -o build/check_rtnl
	./build/check_rtnl
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=log_write,--wrap=time,--wrap=timerfd_create,--wrap=timerfd_settime,--wrap=epoll_ctl,--wrap=close tests/check_guard_monitor.c src/guard_monitor.c src/guard_status.c src/log.c src/util.c -o build/check_guard_monitor
	./build/check_guard_monitor
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=connect,--wrap=send,--wrap=recv tests/check_rci.c src/util.c src/log.c src/config.c src/params.c -o build/check_rci
	./build/check_rci
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_config.c src/config.c src/params.c src/args.c src/util.c src/log.c -o build/check_config
	./build/check_config
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=ipset_create,--wrap=ipset_flush,--wrap=add_cidr_to_ipsets,--wrap=log_write,--wrap=send,--wrap=recv tests/check_ipset_start.c src/ipset_start.c src/ipset_nl.c src/config.c src/params.c src/args.c src/util.c src/log.c -o build/check_ipset_start
	./build/check_ipset_start
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_watchlist.c src/watchlist.c src/util.c src/log.c -o build/check_watchlist
	./build/check_watchlist
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_wlapi.c src/watchlist_api.c src/watchlist.c src/util.c src/log.c -o build/check_wlapi
	./build/check_wlapi
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_routing.c src/routing.c src/watchlist.c src/util.c src/log.c -o build/check_routing
	./build/check_routing
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=ipset_refresh_set_list,--wrap=ipset_add_batch,--wrap=log_write tests/check_cidr_load.c src/geodat.c src/ipset_nl.c src/util.c src/log.c -o build/check_cidr_load
	./build/check_cidr_load
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=send,--wrap=recv,--wrap=realloc,--wrap=log_write tests/check_ipset_refresh.c src/ipset_nl.c src/util.c src/log.c -o build/check_ipset_refresh
	./build/check_ipset_refresh
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_packet_capture.c src/packet_capture.c src/log.c src/util.c -o build/check_packet_capture
	./build/check_packet_capture
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_run_command.c src/util.c -o build/check_run_command
	./build/check_run_command
	sh tests/check_lifecycle.sh

clean:
	rm -rf build/
