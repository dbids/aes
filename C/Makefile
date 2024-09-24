CC=gcc
CFLAGS=-I.
DEPS = aes.h debug.h
OBJ = main.o aes.o debug.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJ) test