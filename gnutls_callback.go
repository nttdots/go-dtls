package dtls_gnutls

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lgnutls
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include "gnutls.h"
*/
import "C"
import "unsafe"

//export export_push_func_callback
func export_push_func_callback(ptr unsafe.Pointer, data unsafe.Pointer, size C.size_t) C.ssize_t {
	go_data := make([]byte, size)
	C.memcpy(unsafe.Pointer(&go_data[0]), data, size)

	s := (*privDataSt)(ptr)
	return C.ssize_t(push_func_callback(s, go_data))
}

//export export_pull_func_callback
func export_pull_func_callback(ptr unsafe.Pointer, data unsafe.Pointer, size C.size_t) C.ssize_t {
	s := (*privDataSt)(ptr)
	go_data, err := pull_func_callback(s, int(size))
	if err != nil {
		C.gnutls_transport_set_errno(s.session, C.EAGAIN)
		return C.ssize_t(-1)
	} else {
		C.memcpy(data, unsafe.Pointer(&go_data[0]), C.size_t(len(go_data)))
		return C.ssize_t(len(go_data))
	}
}

//export export_pull_timeout_func_callback
func export_pull_timeout_func_callback(ptr unsafe.Pointer, ms C.uint) C.int {
	s := (*privDataSt)(ptr)
	return C.int(pull_timeout_func_callback(s, uint(ms)))
}
