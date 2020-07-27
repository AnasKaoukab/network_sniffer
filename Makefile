CFLAGS=-Wall -lpcap
CC=gcc
C_SOURCES=application.c transport.c network.c ethernet.c main.c
OUTPUT=projet
FILESTOREMOVE=$(OUTPUT)

all:
	$(CC) $(C_SOURCES) $(CFLAGS) -o $(OUTPUT)

clean:
	rm $(FILESTOREMOVE)
