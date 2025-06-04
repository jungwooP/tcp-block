all: tcp-block

main.o: mac.h ip.h ethhdr.h tcphdr.h main.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

ip.o: ip.h ip.cpp

mac.o: mac.h mac.cpp

tcp-block: main.o ethhdr.o ip.o mac.o iphdr.o
	g++ main.o ethhdr.o ip.o mac.o iphdr.o -lpcap -o tcp-block

clean:
	rm -f *.o tcp-block
