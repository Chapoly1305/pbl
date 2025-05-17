CC = gcc
CFLAGS = -Wall -O2 -I./src
TARGET = pbl_dat_dump
LIBS = libpbl.a

all: $(TARGET)

$(TARGET): pbl_dat_dump.o
	$(CC) $(CFLAGS) -o $(TARGET) pbl_dat_dump.o $(LIBS)

pbl_dat_dump.o: pbl_dat_dump.c
	$(CC) $(CFLAGS) -c pbl_dat_dump.c

clean:
	rm -f $(TARGET) *.o
