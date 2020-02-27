client_OBJS:= client.o
server_OBJS:= server.o

all: client server

client: $(client_OBJS)
	gcc -o$@ $^

server: $(server_OBJS)
	gcc -o$@ $^

%.o: %.c
	gcc -c -o $@ $<

clean:
	rm -f *.o client server

.PHONY: all clean
