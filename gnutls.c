#include <stdio.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "gnutls.h"
#include "_cgo_export.h"

void call_gnutls_free(void* p) {
	gnutls_free(p);
}

ssize_t push_func(gnutls_transport_ptr_t p, const void *data, size_t size) {
	return export_push_func_callback(p, (void *)data, size);
}

ssize_t pull_func(gnutls_transport_ptr_t p, void* data, size_t size) {
	return export_pull_func_callback(p, data, size);
}

int pull_timeout_func(gnutls_transport_ptr_t p, unsigned int ms) {
	return export_pull_timeout_func_callback(p, ms);
}

void log_output(int level, const char* msg) {
	log_output_callback(level, (char*)msg);
}

