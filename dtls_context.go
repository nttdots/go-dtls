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

void set_sockaddr_in(struct sockaddr_in* sa, char* ip, int port) {
	sa->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &sa->sin_addr);
	sa->sin_port = htons(port);
}

void set_sockaddr_in6(struct sockaddr_in6* sa, char* ip, int port, int scope_id) {
	sa->sin6_family = AF_INET6;
	inet_pton(AF_INET6, ip, &sa->sin6_addr);
	sa->sin6_port = htons(port);
	sa->sin6_scope_id = scope_id;
}*/
import "C"
import (
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"
	log "github.com/sirupsen/logrus"
	sockaddrnet "github.com/jbenet/go-sockaddr/net"
)

const DTLS_PACKET_MTU = 1500

type DTLSCTX struct {
	xcred          C.gnutls_certificate_credentials_t
	priorityCache  C.gnutls_priority_t
	retransTimeout uint
	totalTimeout   uint
}

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func NewDTLSClientContext(caCertFile, certFile, keyFile string) (ctx *DTLSCTX, err error) {
	if !exists(caCertFile) || !exists(certFile) || !exists(keyFile) {
		return nil, errors.New(fmt.Sprintf("file not found. %s or %s or %s", caCertFile, certFile, keyFile))
	}

	log.WithFields(log.Fields{
		"certFile(ca)": caCertFile,
		"certFile":     certFile,
		"keyFile":      keyFile,
	}).Info("create DTLS client context.")

	ctx, err = initialize(caCertFile, certFile, keyFile)
	return
}

func NewDTLSServerContext(caCertFile, crlFile, certFile, keyFile string) (ctx *DTLSCTX, err error) {
	if !exists(caCertFile) || !exists(certFile) || !exists(keyFile) {
		return nil, errors.New(fmt.Sprintf("file not found. %s or %s or %s", caCertFile, certFile, keyFile))
	}

	log.WithFields(log.Fields{
		"certFile(ca)": caCertFile,
		"crlFile":      crlFile,
		"certFile":     certFile,
		"keyFile":      keyFile,
	}).Info("create DTLS server context.")

	ctx, err = initialize(caCertFile, certFile, keyFile)
	if err != nil {
		return
	}

	cCrlfile := C.CString(crlFile)
	defer C.free(unsafe.Pointer(cCrlfile))
	ret := C.gnutls_certificate_set_x509_crl_file(ctx.xcred, cCrlfile, C.GNUTLS_X509_FMT_PEM)
	err = checkGnutlsError(ret, "gnutls_certificate_set_x509_crl_file")
	if err != nil {
		goto Error
	}

	return
Error:
	ctx.Close()
	return

}

func (ctx *DTLSCTX) Listen(server string, establishConnChan chan<- net.Conn, errorChan chan<- error) (scon *DTLS_SERVER_CONTEXT, err error) {

	listenAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return
	}

	scon, err = ctx.initListenerContext(conn, establishConnChan, errorChan)
	if err != nil {
		return
	}

	log.WithField("listen", listenAddr.String()).Info("UDP server ready")
	return
}

/*
 * This function is for the clients to connect the server via DTLS.
 * Parameter format for this function is "server: 'hostname:port'".
 * It returns established DTLS sessions.
*/
func (ctx *DTLSCTX) Connect(server string) (session *DTLS_CLIENT_SESSION, err error) {

	log.WithFields(log.Fields{
		"target": server,
	}).Debug("DTLSCTX::Connect")

	remote, _ := net.ResolveUDPAddr("udp", server)
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return
	}
	//serverHostName := strings.SplitN(server, ":", 2)[0]

	session, err = ctx.initClientSession(conn, "", "")
	if err != nil {
		return
	}

	err = session.connect()
	if err != nil {
		return
	}

	session.showConnectStatus()
	return
}

func (ctx *DTLSCTX) SetTimeout(retransTimeoutSec, totalTimeoutSec uint) {
	ctx.retransTimeout = retransTimeoutSec
	ctx.totalTimeout = totalTimeoutSec
}

/*
 * Set the log level(0-9).
 */
func (ctx *DTLSCTX) SetLogLevel(level int) {
	C.gnutls_global_set_log_level(C.int(level))
}

func CloseAll() {
	C.gnutls_global_deinit()
}

/*
 * Initialize the client session objects.
 */
func (d *DTLSCTX) initClientSession(conn *net.UDPConn, serverHostName, clientHostName string) (clientSession *DTLS_CLIENT_SESSION, err error) {
	var ret C.int
	priorities := C.CString("NORMAL:-VERS-ALL:+VERS-DTLS1.2")
	defer C.free(unsafe.Pointer(priorities))
	clientSession = &DTLS_CLIENT_SESSION{}
	clientSession.conn = conn

	/* Initialize TLS session */
	ret = C.gnutls_init(&(clientSession.session), C.GNUTLS_CLIENT|C.GNUTLS_DATAGRAM)
	err = checkGnutlsError(ret, "gnutls_init")
	if err != nil {
		goto Error
	}

	ret = C.gnutls_priority_set_direct(clientSession.session, priorities, nil)
	err = checkGnutlsError(ret, "gnutls_priority_set_direct")
	if err != nil {
		goto Error
	}

	/* put the x509 credentials to the current session */
	ret = C.gnutls_credentials_set(clientSession.session, C.GNUTLS_CRD_CERTIFICATE, unsafe.Pointer(d.xcred))
	err = checkGnutlsError(ret, "gnutls_credentials_set")
	if err != nil {
		goto Error
	}

	if serverHostName != "" {
		cServerHostName := C.CString(serverHostName)
		defer C.free(unsafe.Pointer(cServerHostName))
		ret = C.gnutls_server_name_set(clientSession.session, C.GNUTLS_NAME_DNS, unsafe.Pointer(cServerHostName), C.size_t(len(serverHostName)))
		err = checkGnutlsError(ret, "gnutls_server_name_set")
		if err != nil {
			goto Error
		}
	}

	return
Error:
	clientSession = nil
	return
}

func (d *DTLSCTX) initListenerContext(conn *net.UDPConn, establishConnChan chan<- net.Conn, errorChan chan<- error) (context *DTLS_SERVER_CONTEXT, err error) {

	var primeBits C.uint

	receiveDataCh := make(chan receiveData, MAX_CLIENT*2)
	establishKeyCh := make(chan string, MAX_CLIENT)
	closingKeyCh := make(chan string, MAX_CLIENT)
	listenStopChan := make(chan chan bool, 1)
	log.WithField("listenStopChan", fmt.Sprintf("%p", listenStopChan)).Debug("create channel")
	clientMap := make(map[string]*sessionContainer)

	context = &DTLS_SERVER_CONTEXT{}
	context.ctx = d
	context.conn = conn
	context.cookieKey = (*C.gnutls_datum_t)(C.malloc(C.size_t(C.sizeof_gnutls_datum_t)))
	context.receiveDataCh = receiveDataCh
	context.establishKeyCh = establishKeyCh
	context.closingKeyCh = closingKeyCh
	context.listenStopChan = listenStopChan
	context.clientMap = clientMap
	context.connRecvChan = establishConnChan
	context.connErrorChan = errorChan

	ret := C.gnutls_dh_params_init(&context.dhParam)
	err = checkGnutlsError(ret, "gnutls_dh_params_init")
	if err != nil {
		goto Error
	}

	primeBits = C.gnutls_sec_param_to_pk_bits(C.GNUTLS_PK_DH, C.GNUTLS_SEC_PARAM_MEDIUM)
	ret = C.gnutls_dh_params_generate2(context.dhParam, primeBits)
	err = checkGnutlsError(ret, "gnutls_dh_params_generate2")
	if err != nil {
		goto Error2
	}
	C.gnutls_certificate_set_dh_params(d.xcred, context.dhParam)

	ret = C.gnutls_key_generate(context.cookieKey, C.GNUTLS_COOKIE_KEY_SIZE)
	err = checkGnutlsError(ret, "gnutls_key_generate")
	if err != nil {
		goto Error2
	}

	log.Debugf("TLS session context initialized: %+v", context)
	go context.receiveLoop()
	go context.sessionLifetimeLoop()

	return
Error2:
	C.gnutls_dh_params_deinit(context.dhParam)
Error:
	C.free(unsafe.Pointer(context.cookieKey))
	return nil, err
}

func (d *DTLSCTX) Close() {
	log.WithFields(log.Fields{
		"instance": fmt.Sprintf("%p", d),
	}).Infof("DTLS context close.")

	C.gnutls_certificate_free_credentials(d.xcred)
	C.gnutls_priority_deinit(d.priorityCache)
	C.free(unsafe.Pointer(d))
}

/*
 * Convert net.UDPAddr to C.sockaddr_in or C.sockaddr_iny
 */
func toSocketaddr(addr *net.UDPAddr) (*C.struct_sockaddr, int) {
	var sock *C.struct_sockaddr
	var length int

	if addr.IP.To4() != nil {
		s := new(C.struct_sockaddr_in)
		ip := C.CString(addr.IP.To4().String())
		defer C.free(unsafe.Pointer(ip))
		C.set_sockaddr_in(s, ip, C.int(addr.Port))

		sock = (*C.struct_sockaddr)(unsafe.Pointer(s))
		length = C.sizeof_struct_sockaddr_in
	} else {
		s := new(C.struct_sockaddr_in6)
		ip := C.CString(addr.IP.To16().String())
		defer C.free(unsafe.Pointer(ip))
		C.set_sockaddr_in6(s, ip, C.int(addr.Port), C.int(sockaddrnet.IP6ZoneToInt(addr.Zone)))

		sock = (*C.struct_sockaddr)(unsafe.Pointer(s))
		length = C.sizeof_struct_sockaddr_in6
	}

	return sock, length
}
