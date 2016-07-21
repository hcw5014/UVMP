CC = gcc
CFLAGS  = -O3 -Wall -ggdb -O0\
	-I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include  \
	 \
	-I/usr/include/pbc -I/usr/local/include/pbc

LDFLAGS = -O3 -Wall \
	-lglib-2.0  \
	-Wl,-rpath /usr/local/lib -lgmp \
	-Wl,-rpath /usr/local/lib -lpbc \
	-lbswabe \
	-lcrypto -lcrypto 

#OBJS = common.o policy_lang.o client_end.o
#TARGETS  = client

#all: $(TARGETS) 

#$(TARGETS): $(OBJS)
#	$(CC) -o $(TARGETS) $(OBJS)  $(LDFLAGS)

client: common.o policy_lang.o client_end.o
	$(CC) -o client common.o policy_lang.o client_end.o $(LDFLAGS)

server: common.o policy_lang.o server_end.o
	$(CC) -o server common.o policy_lang.o server_end.o $(LDFLAGS)

setPolicy: common.o policy_lang.o setPolicy.o
	$(CC) -o setPolicy common.o policy_lang.o setPolicy.o $(LDFLAGS)

common.o: common.c common.h
	$(CC) -c common.c $(CFLAGS)

policy_lang.o: policy_lang.c common.h policy_lang.h
	$(CC) -c policy_lang.c $(CFLAGS)

client_end.o: client_end.c common.h policy_lang.h
	$(CC) -c client_end.c $(CFLAGS)

setPolicy.o: setPolicy.c common.h policy_lang.h
	$(CC) -c setPolicy.c $(CFLAGS)

server_end.o: server_end.c common.h policy_lang.h
	$(CC) -c server_end.c $(CFLAGS)

clean_client:
	rm -f client common.o policy_lang.o client_end.o

clean_server:
	rm -f server common.o policy_lang.o server_end.o

clean_setPolicy:
	rm -f setPolicy common.o policy_lang.o setPolicy.o
