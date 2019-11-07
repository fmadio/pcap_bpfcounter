OBJS =
OBJS += parser.o
OBJS += fProfile.o
OBJS += output.o

LOBJS =
LOBJS += lmain.o

DEF = 
DEF += -g
DEF += -O1
DEF += --std=c99 
DEF += -I../
DEF += -I./luajit/src
DEF += -D_LARGEFILE64_SOURCE 
DEF += -D_GNU_SOURCE 

LIBS =
LIBS += luajit/src/libluajit.a 
LIBS += libpcap/libpcap.a 
LIBS += -ldl

LDFLAG = 
LDFLAG += -lm
LDFLAG += -lc
LDFLAG += -lpthread
LDFLAG += -g

%.o: %.c
	gcc $(DEF) -c -o $@ -g $<

%.o: %.lua
	 objcopy --input binary --output elf64-x86-64  --binary-architecture i386  $<  $@ 

all: $(LIBS) $(OBJS) $(LOBJS)
	gcc $(DEF) -c -o main.o -g main.c
	gcc $(LDFLAG) -o pcap_bpfcounter main.o $(OBJS) $(LIBS) lmain.o
	./MapGen.lua pcap_bpfcounter
	cat symbol.bin >> pcap_bpfcounter

clean:
	rm -f $(OBJS)
	rm -f $(LOBJS)
	rm -f pcap_bpfcounter 
	rm -f symbol.bin 

