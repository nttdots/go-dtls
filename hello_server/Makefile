.PHONY: clean all
CFLAGS := -DCOMPILE_SAMPLE
LDLIBS := -lgnutls

hello_server: main.go $(wildcard ../*.go)
	go build -v

clean:
	$(RM) hello_server

