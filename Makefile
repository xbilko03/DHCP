CC=gcc
CFLAGS= -Wall 
DEPS = dhcp-stats.c btree.h btree.c -lcurses -lpcap -lm
PROGNAME = dhcp-stats

$(PROGNAME): $(DEPS)
	$(CC) $(DEPS) $(CFLAGS) -o $(PROGNAME)

run-file: $(DEPS)
	$(CC) $(DEPS) $(CFLAGS) -o $(PROGNAME)
	./$(PROGNAME) -r tests/1.pcapng 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24
	./$(PROGNAME) -r tests/2.pcapng 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24
	./$(PROGNAME) -r tests/3.pcapng 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24
	./$(PROGNAME) -r tests/4.pcapng 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24
	./$(PROGNAME) -r tests/5.pcapng 192.168.60.10/20 192.168.0.0/22 172.16.32.0/24
	./$(PROGNAME) -r tests/6.pcap 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24

run-int: $(DEPS)
	$(CC) $(DEPS) $(CFLAGS) -o $(PROGNAME)
	sudo ./$(PROGNAME) -i any 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24

clean:
	rm $(PROGNAME)

