CC=gcc
CFLAGS=-pthread -O0 -g -Wall

all: speedjournal

diary: speedjournal.c
	$(CC) $(CFLAGS) speedjournal.c -o demo-speedjournal

clean:
	rm -f speedjournal
