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
	"net"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

type DTLS_SERVER_CONTEXT struct {
	ctx            *DTLSCTX
	cookieKey      *C.gnutls_datum_t // c heap
	dhParam        C.gnutls_dh_params_t
	conn           *net.UDPConn
	receiveDataCh  chan receiveData
	establishKeyCh chan string
	closingKeyCh   chan string
	clientMap      map[string]*sessionContainer

	connRecvChan   chan<- net.Conn
	connErrorChan  chan<- error
	listenStopChan chan chan bool
}

func (listener *DTLS_SERVER_CONTEXT) Close() {
	log.Infof("DTLS_SERVER_CONTEXT -- Close [%p]", listener)
	ch := make(chan bool)
	listener.listenStopChan <- ch
	<-ch
	C.gnutls_dh_params_deinit(listener.dhParam)
	C.free(unsafe.Pointer(listener.cookieKey))
	C.free(unsafe.Pointer(listener))
}

/*
 * DTLS server receive main loop.
 */
func (listener *DTLS_SERVER_CONTEXT) receiveLoop() {
	buffer := make([]byte, DTLS_PACKET_MTU)

	log.Info("start - socket monitoring loop.")
loop:
	for {
		select {
		case c, ok := <-listener.listenStopChan:
			if ok {
				log.Info("stop - socket monitoring loop.")
			} else {
				log.Warn("stop - socket monitoring loop.")
			}

			// close existing sessions.
			close(listener.closingKeyCh)
			close(listener.establishKeyCh)
			close(listener.receiveDataCh)
			listener.conn.Close()
			c <- true
			break loop
		default:
			// 100msec間ポート監視. 擬似的にlistenStopChanとソケットを並行監視する
			listener.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, from, err := listener.conn.ReadFromUDP(buffer)

			if err != nil {
				switch e := err.(type) {
				case net.Error:
					if e.Timeout() {
						continue loop
					}
					if e.Temporary() {
						listener.connErrorChan <- e
						continue loop
					}
					go listener.Close()
					continue loop
				default:
					go listener.Close()
					log.WithError(e).Error("error - socket monitoring loop")
					continue loop
				}
			}
			if n <= 0 {
				continue loop
			}

			data := make([]byte, n)
			copy(data, buffer[:n])

			log.WithFields(log.Fields{
				"from":   from.String(),
				"length": len(data),
			}).Info("receive - socket monitoring loop")

			listener.receiveDataCh <- receiveData{data, from, err}
		}
	}
}

/*
 * Verify cookies in the ClientHello. It is for the stateless cookies.
 */
func (listener *DTLS_SERVER_CONTEXT) verifyCookie(from *net.UDPAddr, data []byte, pre_state *C.gnutls_dtls_prestate_st) bool {
	from_addr, length := toSocketaddr(from)

	ret := C.gnutls_dtls_cookie_verify(listener.cookieKey, unsafe.Pointer(from_addr), C.size_t(length),
		unsafe.Pointer(&data[0]), C.size_t(len(data)), pre_state)

	return ret >= 0
}

func (listener *DTLS_SERVER_CONTEXT) sessionLifetimeLoop() {
	for {
		select {
		case recvData, ok := <-listener.receiveDataCh:
			if !ok { // this channel has been closed.
				break
			}
			if recvData.err != nil { // socket error
				listener.connErrorChan <- recvData.err
				continue
			}

			key := recvData.from.String()
			// DTLS セッション確立済みの場合. gnutlsオブジェクトに流す
			if session, ok := listener.clientMap[key]; ok {
				log.WithFields(log.Fields{
					"key":           session.key,
					"state":         "connected",
					"receiveLength": len(recvData.data),
				}).Info("receive DTLS packet.")
				session.socketReceiveCh <- recvData.data
				continue
			}

			pre_state := new(C.gnutls_dtls_prestate_st)
			if listener.verifyCookie(recvData.from, recvData.data, pre_state) {
				// DTLSクッキーが正常な場合. gnutlsオブジェクトを作成し、以降のパケットはそちらに流す
				session, err := listener.initSession(recvData.from, pre_state)
				if err == nil {
					listener.clientMap[session.key] = session
					go listener.waitHandshake(session)
					log.WithFields(log.Fields{
						"key":           session.key,
						"state":         "clientHello(with cookie)",
						"receiveLength": len(recvData.data),
					}).Info("receive DTLS packet, create gnutls session.")

					session.socketReceiveCh <- recvData.data
				} else {
					listener.connErrorChan <- err
					continue
				}
			} else {
				// DTLSクッキーがない、もしくは不正な場合. 再送信を促す
				log.WithFields(log.Fields{
					"key":           key,
					"state":         "clientHello(without cookie)",
					"receiveLength": len(recvData.data),
				}).Info("receive DTLS packet, send cookie.")

				err := listener.sendCookie(recvData.from, pre_state)
				if err != nil {
					listener.connErrorChan <- err
				}
				continue
			}
		case key, ok := <-listener.establishKeyCh:
			if ok {
				session, ok := listener.clientMap[key]
				if ok {
					session.dtls_connected = true
					session.cn = getClientCN(session.session)

					log.WithFields(log.Fields{
						"client": session.client.String(),
						"queue": len(listener.connRecvChan),
					}).Info("Handshake was completed.")
					listener.connRecvChan <- *session
				}
			}
		case key, ok := <-listener.closingKeyCh:
			if ok {
				log.WithField("key", key).Infof("closing DTLS session.")
				listener.closeSession(key)
			} else {
				log.WithField("key", "all").Infof("closing DTLS sessions.")
				for key := range listener.clientMap {
					// close all active DTLS sessions.
					listener.closeSession(key)
				}
				listener.closingKeyCh = nil
			}
		}
	}
}
