
.PHONY: clean all
CFLAGS := -DCOMPILE_SAMPLE
LDLIBS := -lgnutls

all: test_server test_client

clean:
	$(RM) -f test_server
	$(RM) -f test_client
	$(RM) -r *.o

test_server: test_server.o

test_client: test_client.o udp.o
