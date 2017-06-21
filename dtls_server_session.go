package dtls_gnutls

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lgnutls

#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <gnutls/x509.h>
#include "gnutls.h"
*/
import "C"
import (
	_ "encoding/hex"
	"errors"
	"net"
	"time"
	"unsafe"

	log "github.com/Sirupsen/logrus"
)

const MAX_CLIENT = 20

type DTLSServerConn interface {
	GetClientCN() string
}

/*
DTLS server session container
 */
type sessionContainer struct {
	context         *DTLS_SERVER_CONTEXT
	key             string
	session         C.gnutls_session_t
	preState        *C.gnutls_dtls_prestate_st
	privData        *privDataSt // C heap
	client          *net.UDPAddr
	socketReceiveCh chan []byte
	dtls_connected  bool
	cn              string
}

/*
received packet data
 */
type receiveData struct {
	data []byte
	from *net.UDPAddr
	err  error
}

/*
gnutls コールバック関数のためのセッション固有データ
 */
type privDataSt struct {
	ctx     *DTLS_SERVER_CONTEXT
	client  *net.UDPAddr
	session C.gnutls_session_t
	dataCh  <-chan []byte
}

func (s sessionContainer) Read(b []byte) (n int, err error) {
	ret := C.int(C.GNUTLS_E_AGAIN)
	b_ptr := unsafe.Pointer(&b[0])
	b_len := C.size_t(len(b))
	sequence := make([]C.uchar, 8)
	sequence_ptr := (*C.uchar)(unsafe.Pointer(&sequence[0]))

	for {
		ret = C.int(C.gnutls_record_recv_seq(s.session, b_ptr, b_len, sequence_ptr))
		if ret == C.GNUTLS_E_AGAIN || ret == C.GNUTLS_E_INTERRUPTED {
			continue
		}
		err := checkGnutlsError(ret, "gnutls_record_recv_seq")
		if err == nil {
			break
		} else {
			if err.(Error).is_fatal {
				return 0, err
			} else {
				log.Errorf("sessionContainer::Read -- Warning: %s", err.Error())
			}
		}
	}
	return int(ret), nil
}

func (s sessionContainer) Write(b []byte) (n int, err error) {
	ret := C.int(C.gnutls_record_send(s.session, unsafe.Pointer(&b[0]), C.size_t(len(b))))
	err = checkGnutlsError(ret, "gnutls_record_recv_seq")

	if err == nil {
		return int(ret), nil
	} else {
		return 0, err
	}
}

func (s sessionContainer) LocalAddr() net.Addr {
	return nil
}

func (s sessionContainer) RemoteAddr() net.Addr {
	return s.client
}

func (s sessionContainer) SetDeadline(t time.Time) error {
	duration := t.Sub(time.Now())
	d := int(duration.Nanoseconds() / 1000) // milliseconds
	if d < 0 {
		return errors.New("time must be in the future.")
	}

	C.gnutls_dtls_set_timeouts(s.session, C.uint(d/5), C.uint(d))
	return nil
}

func (s sessionContainer) SetReadDeadline(t time.Time) error {
	return s.SetDeadline(t)
}

func (s sessionContainer) SetWriteDeadline(t time.Time) error {
	return s.SetDeadline(t)
}

func (s sessionContainer) Close() error {
	log.Infof("sessionContainer::Close session: [%p]", s.session)
	s.context.closingKeyCh <- s.key
	return nil
}

func (s sessionContainer) GetClientCN() string {
	if s.dtls_connected {
		return s.cn
	} else {
		return ""
	}
}

/*
 Close this DTLS session.
 Since this function deals with clientMap in the DTLSServerContext,
 it may cause the race conditions on the resource without being called from sessionLifetimeLoop.
*/
func (listener *DTLS_SERVER_CONTEXT) closeSession(key string) {
	session, ok := listener.clientMap[key]
	if ok {
		delete(listener.clientMap, key)
		if session.dtls_connected {
			C.gnutls_bye(session.session, C.GNUTLS_SHUT_WR)
		}
		C.gnutls_deinit(session.session)
		C.free(unsafe.Pointer(session.privData))
		close(session.socketReceiveCh)
	}
}

/*
 * Wait until the handshake to be completed.
 */
func (listener *DTLS_SERVER_CONTEXT) waitHandshake(ctn *sessionContainer) {
	log.Infof("DTLS_SERVER_CONTEXT::waitHandshake -- client:[%s]", ctn.key)
	ret := C.int(C.GNUTLS_E_AGAIN)
	for ret == C.GNUTLS_E_INTERRUPTED || ret == C.GNUTLS_E_AGAIN {
		ret = C.gnutls_handshake(ctn.session)
	}

	err := checkGnutlsError(ret, "gnutls_handshake")
	if err != nil {
		listener.connErrorChan <- err
		ctn.Close()
	} else {
		listener.establishKeyCh <- ctn.key
	}
}

/*
 * Send cookies to the clients for the handshakes.
 */
func (listener *DTLS_SERVER_CONTEXT) sendCookie(from *net.UDPAddr, pre_state *C.gnutls_dtls_prestate_st) (err error) {

	from_addr, length := toSocketaddr(from)
	// allocate from C heap / avoid GC
	s := (*privDataSt)(C.malloc(C.size_t(unsafe.Sizeof(privDataSt{}))))
	s.ctx = listener
	s.session = nil
	s.client = from
	s.dataCh = nil
	defer C.free(unsafe.Pointer(s))

	log.Infof("DTLS_SERVER_CONTEXT::sendCookie -- client: %s", from.String())

	ret := C.gnutls_dtls_cookie_send(
		listener.cookieKey,
		unsafe.Pointer(from_addr), C.size_t(length),
		pre_state,
		C.gnutls_transport_ptr_t(s),
		C.gnutls_push_func(C.push_func))

	err = checkGnutlsError(ret, "gnutls_dtls_cookie_send")
	return
}

/*
 * Initialize DTLS sessions.
 */
func (listener *DTLS_SERVER_CONTEXT) initSession(from *net.UDPAddr, pre_state *C.gnutls_dtls_prestate_st) (container *sessionContainer, err error) {

	container = (*sessionContainer)(C.malloc(C.size_t(unsafe.Sizeof(sessionContainer{}))))
	var dataCh chan []byte
	var privateData *privDataSt

	ret := C.gnutls_init(&container.session, C.GNUTLS_SERVER|C.GNUTLS_DATAGRAM)
	err = checkGnutlsError(ret, "gnutls_init")
	if err != nil {
		goto Error
	}

	ret = C.gnutls_priority_set(container.session, listener.ctx.priorityCache)
	err = checkGnutlsError(ret, "gnutls_priority_set")
	if err != nil {
		goto ErrorOnSessionInitialized
	}

	ret = C.gnutls_credentials_set(container.session, C.GNUTLS_CRD_CERTIFICATE, unsafe.Pointer(listener.ctx.xcred))
	err = checkGnutlsError(ret, "gnutls_credentials_set")
	if err != nil {
		goto ErrorOnSessionInitialized
	}

	C.gnutls_certificate_server_set_request(container.session, C.GNUTLS_CERT_REQUEST)

	C.gnutls_dtls_prestate_set(container.session, pre_state)
	C.gnutls_dtls_set_mtu(container.session, DTLS_PACKET_MTU)

	dataCh = make(chan []byte, 6)
	// allocate from C heap / avoid GC
	privateData = (*privDataSt)(C.malloc(C.size_t(unsafe.Sizeof(privDataSt{}))))
	privateData.ctx = listener
	privateData.session = container.session
	privateData.client = from
	privateData.dataCh = dataCh

	C.gnutls_transport_set_ptr(container.session, (C.gnutls_transport_ptr_t)(unsafe.Pointer(privateData)))
	C.gnutls_transport_set_push_function(container.session, C.gnutls_push_func(C.push_func))
	C.gnutls_transport_set_pull_function(container.session, C.gnutls_pull_func(C.pull_func))
	C.gnutls_transport_set_pull_timeout_function(container.session, C.gnutls_pull_timeout_func(C.pull_timeout_func))

	container.context = listener
	container.key = from.String()
	container.preState = pre_state
	container.privData = privateData
	container.client = from
	container.socketReceiveCh = dataCh
	container.dtls_connected = false
	container.cn = ""

	return

ErrorOnSessionInitialized:
	C.gnutls_deinit(container.session)
	C.free(unsafe.Pointer(container))
Error:
	return nil, err
}

/*
 * The callback function for the data transfer.
 */
func push_func_callback(s *privDataSt, data []byte) C.int {
	log.WithFields(log.Fields{
		"channel": s.client.String(),
	}).Info("(push_func_callback) send to client.")
	//log.Debugf("data: \n%s", hex.Dump(data))

	n, err := s.ctx.conn.WriteToUDP(data, s.client)
	if err == nil {
		return C.int(n)
	} else {
		log.WithError(err).Error("(push_func_callback) socket write error.")

		if err.(net.Error).Timeout() {
			return C.GNUTLS_E_TIMEDOUT
		} else {
			return C.GNUTLS_E_PUSH_ERROR
		}
	}
}

/*
 * The callback function for the data receive.
 */
func pull_func_callback(s *privDataSt, maxLength int) (data []byte, err error) {
	select {
	case data = <-s.dataCh:
		dataLen := len(data)
		log.WithFields(log.Fields{
			"channel": s.client.String(),
		}).Info("(pull_func_callback) receive from client.")
		//log.Debugf("data: \n%s", hex.Dump(data))

		if maxLength < dataLen {
			d := make([]byte, maxLength)
			copy(d, data)
			return d, nil
		} else {
			return data, nil
		}
	}
}

/*
 * Timeout handler on the data receiving.
 */
func pull_timeout_func_callback(s *privDataSt, msec uint) int {
	deadline := time.Now().Add(time.Duration(msec) * time.Millisecond)

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			if time.Now().After(deadline) {
				return 0
			}
			if len(s.dataCh) > 0 {
				return 1
			}
		}
	}
}
