package dtls_gnutls

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lgnutls
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include "gnutls.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"
	log "github.com/sirupsen/logrus"
)

type DTLS_CLIENT_SESSION struct {
	session C.gnutls_session_t // reference type
	conn    *net.UDPConn
	file	*os.File
}

func (d *DTLS_CLIENT_SESSION) checkServerCn(cn string) (err error) {
	var ret C.int
	c_cn := C.CString(cn)
	defer C.free(unsafe.Pointer(c_cn))
	c_ln := len(cn)

	ret = C.gnutls_server_name_set(d.session, C.GNUTLS_NAME_DNS, unsafe.Pointer(c_cn), C.size_t(c_ln))
	if int(ret) < 0 {
		err = errors.New(fmt.Sprintf("gnutls_server_name_set error code:%d", ret))
		return
	}

	return
}

func (d *DTLS_CLIENT_SESSION) setTimeout(retrans, total uint) {
	C.gnutls_dtls_set_timeouts(d.session, C.uint(retrans), C.uint(total))
	C.gnutls_handshake_set_timeout(d.session, C.GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT)
}

func (d *DTLS_CLIENT_SESSION) connect() (err error) {
	var ret C.int

	d.file, err = d.conn.File()
	if err != nil {
		return
	}
	fd := int(d.file.Fd())

	C.gnutls_transport_set_int2(d.session, C.int(fd), C.int(fd))
	C.gnutls_dtls_set_mtu(d.session, DTLS_PACKET_MTU)

	for ret = C.GNUTLS_E_AGAIN; ret == C.GNUTLS_E_INTERRUPTED || ret == C.GNUTLS_E_AGAIN; {
		ret = C.gnutls_handshake(d.session)
		if ret < 0 {
			fatal := C.gnutls_error_is_fatal(ret) != 0
			if fatal {
				break
			}
		}
	}

	if int(ret) < 0 {
		msg := C.gnutls_strerror(ret)
		log.WithFields(log.Fields{
			"channel": d.conn.LocalAddr().String(),
			"message": C.GoString(msg),
		}).Error("DTLS client connect error.")
		err = errors.New(fmt.Sprintf("DTLS_CLIENT_SESSION::connect - handshake failed. channel:[%s] message: %s", d.conn.LocalAddr().String(), C.GoString(msg)))
	}
	return
}

func (d *DTLS_CLIENT_SESSION) showConnectStatus() {
	desc := C.gnutls_session_get_desc(d.session)
	defer C.call_gnutls_free(unsafe.Pointer(desc))
	log.Infof("session info: %s", C.GoString(desc))
}

// Receive TLS records via client sessions.
func (d *DTLS_CLIENT_SESSION) Read(b []byte) (n int, err error) {
	ret := C.gnutls_record_recv(d.session, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	iret := C.int(ret)
	lret := int64(ret)
	if lret == 0 {
		log.Print("peer has closed the DTLS connection.")
		return 0, nil
	} else if lret < 0 && C.gnutls_error_is_fatal(iret) == C.int(0) {
		log.Warnf("warning: %s", C.GoString(C.gnutls_strerror(iret)))
		return 0, nil
	} else if lret < 0 {
		message := C.GoString(C.gnutls_strerror(iret))
		log.Errorf("Read error: %s", message)
		return 0, errors.New(message)
	}

	n = int(ret)
	log.Infof("received %d bytes.", n)
	return
}

func (d *DTLS_CLIENT_SESSION) Write(b []byte) (n int, err error) {
	ret := C.gnutls_record_send(d.session, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	iret := C.int(ret)
	if ret >= 0 {
		return int(ret), nil
	} else {
		message := C.GoString(C.gnutls_strerror(iret))
		log.Errorf("DTLS_CLIENT_SESSION::Write -- Write error: %s", message)
		return 0, errors.New(message)
	}
}

/*
 * Close DTLS sessions on session terminations.
 */
func (d *DTLS_CLIENT_SESSION) Close() error {
	log.WithFields(log.Fields{
		"instance": fmt.Sprintf("%p", d),
	}).Infof("close DTLS_CLIENT_SESSION")

	C.gnutls_bye(d.session, C.GNUTLS_SHUT_WR)
	C.gnutls_deinit(d.session)
	err := d.conn.Close()
	if err != nil {
		log.WithError(err).Error("DTLS original connection close error.")
	}
	if d.file != nil {
		err := d.file.Close()
		if err != nil {
			log.WithError(err).Error("DTLS duped connection close error.")
		}
	}

	return nil
}

func (d *DTLS_CLIENT_SESSION) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *DTLS_CLIENT_SESSION) RemoteAddr() net.Addr {
	return d.conn.RemoteAddr()
}

func (d *DTLS_CLIENT_SESSION) SetDeadline(t time.Time) error {
	sec := time.Now().Sub(t)
	if sec < 0 {
		return errors.New("deadline must be future time.")
	}
	d.setTimeout(uint(sec.Seconds()), uint(sec.Seconds()))
	return nil
}

func (d *DTLS_CLIENT_SESSION) SetReadDeadline(t time.Time) error {
	return d.SetDeadline(t)
}

func (d *DTLS_CLIENT_SESSION) SetWriteDeadline(t time.Time) error {
	return d.SetDeadline(t)
}
