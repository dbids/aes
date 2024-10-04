CC=gcc
CFLAGS=-I.
DEPS = aes.h ecb.h debug.h
OBJ = main.o aes.o ecb.o debug.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJ) test
