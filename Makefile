TARGETS = dns_monitor
DEV=enp6s18

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: dns_monitor.bpf.o 

dns_monitor.bpf.o: dns_monitor.bpf.c
	clang \
	    -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<

clean: 
	- rm *.bpf.o
	- rm -f dns_monitor
	- sudo tc qdisc del dev $(DEV) clsact

up: load list attach watch

down: detach unload

load:
	sudo tc qdisc add dev $(DEV) clsact

attach: load dns_monitor.bpf.o
	sudo tc filter add dev $(DEV) egress bpf obj dns_monitor.bpf.o sec classifier

watch:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

detach:
	sudo tc filter del dev $(DEV) egress

list:
	sudo tc filter show dev $(DEV) egress

user: dns_monitor.bpf.o dns_monitor
	sudo ./dns_monitor

dns_monitor: dns_monitor.c dns_monitor.bpf.o
	gcc -O2 -fsanitize=address -g -Wall -I/usr/include -o dns_monitor dns_monitor.c -lbpf -lelf -lz

