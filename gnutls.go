package dtls_gnutls

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lgnutls
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include "gnutls.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

type Error struct {
	error
	is_fatal bool
}

func init() {
	var ret C.int
	var cret *C.char

	version := C.CString("3.3.24")
	defer C.free(unsafe.Pointer(version))

	cret = C.gnutls_check_version(version)
	if cret == nil {
		log.Fatalf("GnuTLS 3.3.24 or later required.")
	}

	ret = C.gnutls_global_init()
	if int(ret) < 0 {
		log.Fatalf("gnutls_global_init error code:%d", ret)
	}

	C.gnutls_global_set_log_level(0)
	C.gnutls_global_set_log_function(C.gnutls_log_func(C.log_output))
}

//export log_output_callback
func log_output_callback(level C.int, pointer *C.char) {
	msg := C.GoString(pointer)
	log.Infof("info: level:%d, %s", level, msg)
}

func initialize(cacert, cert, key string) (context *DTLSCTX, err error) {
	var ret C.int
	context = (*DTLSCTX)(C.malloc(C.size_t(unsafe.Sizeof(DTLSCTX{}))))
	c_cert := C.CString(cert)
	c_key := C.CString(key)
	c_cafile := C.CString(cacert)
	priority := C.CString("NORMAL:-VERS-ALL:+VERS-DTLS1.2:-KX-ALL:+ECDHE-RSA:%SERVER_PRECEDENCE")
	defer C.free(unsafe.Pointer(c_cert))
	defer C.free(unsafe.Pointer(c_key))
	defer C.free(unsafe.Pointer(c_cafile))
	defer C.free(unsafe.Pointer(priority))

	log.Debugf("context: %p, priorityCache: %p", context, context.priorityCache)

	/* X509 stuff */
	ret = C.gnutls_certificate_allocate_credentials(&(context.xcred))
	err = checkGnutlsError(ret, "gnutls_certificate_allocate_credentials")
	if err != nil {
		goto Error
	}

	/* sets the trusted cas file */
	ret = C.gnutls_certificate_set_x509_trust_file(context.xcred, c_cafile, C.GNUTLS_X509_FMT_PEM)
	err = checkGnutlsError(ret, "gnutls_certificate_set_x509_trust_file")
	if err != nil {
		goto Error
	}

	ret = C.gnutls_certificate_set_x509_key_file(context.xcred, c_cert, c_key, C.GNUTLS_X509_FMT_PEM)
	err = checkGnutlsError(ret, "gnutls_certificate_set_x509_key_file")
	if err != nil {
		goto ErrorOnInitialized
	}

	ret = C.gnutls_priority_init(&context.priorityCache, priority, nil)
	err = checkGnutlsError(ret, "gnutls_priority_init")
	if err != nil {
		goto ErrorOnInitialized
	}

	context.retransTimeout = 1
	context.totalTimeout = 60

	return context, nil
ErrorOnInitialized:
	C.gnutls_certificate_free_credentials(context.xcred)
	C.gnutls_priority_deinit(context.priorityCache)
Error:
	C.free(unsafe.Pointer(context.priorityCache))
	C.free(unsafe.Pointer(context))
	return nil, err
}

func getClientCN(session C.gnutls_session_t) (cn string) {
	const methodName = "getClientCN"

	var ret C.int
	var err error
	var cert C.gnutls_x509_crt_t
	var cert_list *C.gnutls_datum_t
	var cert_list_size C.uint
	// The specification does not specify the max length of DN.
	// We employ 256 bytes after the example of ActiveDirectory.
	dn_buffer := make([]byte, 256)

	if C.gnutls_certificate_type_get(session) != C.GNUTLS_CRT_X509 {
		log.Errorf("error: this session is not certification by x509.")
		return ""
	}

	cert_list = C.gnutls_certificate_get_peers(session, &cert_list_size)
	if cert_list_size > 0 {
		ret = C.gnutls_x509_crt_init(&cert)
		err = checkGnutlsError(ret, "gnutls_x509_crt_init")
		if err != nil {
			log.Errorf("error: %s -- %s", methodName, err.Error())
			return ""
		}
		defer C.gnutls_x509_crt_deinit(cert)
		ret = C.gnutls_x509_crt_import(cert, cert_list, C.GNUTLS_X509_FMT_DER)
		err = checkGnutlsError(ret, "gnutls_x509_crt_import")
		if err != nil {
			log.Errorf("error: %s -- %s", methodName, err.Error())
			return ""
		}
		dn_size := C.size_t(len(dn_buffer))
		ret = C.gnutls_x509_crt_get_dn(cert, (*C.char)(unsafe.Pointer(&dn_buffer[0])), &dn_size)
		if ret == C.GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE {
			return ""
		}
		err = checkGnutlsError(ret, "gnutls_x509_crt_get_dn")
		if err != nil {
			log.Errorf("error: %s -- %s", methodName, err.Error())
			return ""
		}

		dn := string(dn_buffer[:dn_size])
		index_start := strings.Index(dn, "CN=")
		index_last := int(dn_size)
		if index_start == -1 {
			log.Errorf("error: getClientCN -- DN parse error: %s", dn)
			return ""
		}

		skip := false
		escapeChar, _ := utf8.DecodeRuneInString("\\")
		commaChar, _ := utf8.DecodeRuneInString(",")

		for index, runeValue := range dn {
			if index < index_start {
				continue
			}
			if skip {
				skip = false
				continue
			}
			if runeValue == escapeChar {
				skip = true
				continue
			}
			if runeValue == commaChar {
				index_last = index
				break
			}
		}
		cn = dn[index_start+3: index_last]
	} else {
		cn = ""
	}
	return
}

/*
 * Convert gnutls errors to go error structures.
 */
func checkGnutlsError(retcode C.int, funcName string) (err error) {
	if int(retcode) < 0 {
		msg_ptr := C.gnutls_strerror(retcode)
		msg := C.GoString(msg_ptr)
		is_fatal := C.gnutls_error_is_fatal(retcode) != C.int(0)
		err = Error{
			errors.New(fmt.Sprintf("%s error code: %d, message: %s", funcName, int(retcode), msg)),
			is_fatal,
		}
	}
	return
}
