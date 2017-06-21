#ifndef GO_GNUTLS_H
#define GO_GNUTLS_H

#include <gnutls/x509.h>

void call_gnutls_free(void* p);

ssize_t push_func(gnutls_transport_ptr_t p, const void *data, size_t size);
ssize_t pull_func(gnutls_transport_ptr_t p, void* data, size_t size);
int pull_timeout_func(gnutls_transport_ptr_t p, unsigned int ms);
void log_output(int level, const char* msg);
void print_x509_certificate_info(gnutls_session_t session);

#endif
