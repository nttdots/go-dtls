package dtls_gnutls_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	dtls_gnutls "github.com/nttdots/go-dtls"
)

func TestNewDTLSClientContext(t *testing.T) {
	log.Print("-- TestNewDTLSClientContext")

	ctx, err := dtls_gnutls.NewDTLSClientContext("ca-cert.pem", "client-cert.pem", "client-key.pem")
	if err != nil {
		t.Error(err)
		return
	}
	log.Infof("ctx: %+v", ctx)
	defer ctx.Close()

	session, err := ctx.Connect("localhost:11112")
	if err != nil {
		t.Error(err)
		return
	}

	defer session.Close()

	send_string := "client abcde"
	expected := len(send_string)

	n, err := session.Write([]byte(send_string))
	if err != nil {
		t.Errorf("send data error. %s", err)
	}
	if n != expected {
		t.Errorf("got %v, want %v", n, expected)
	}

	buf := make([]byte, 1500)
	n, err = session.Read(buf)
	if err != nil {
		t.Errorf("receive data error. %s", err)
	}
	if n != expected {
		t.Errorf("got %v, want %v", n, expected)
	}
	if string(buf[:n]) != send_string {
		t.Errorf("got %v, want %v", string(buf[:n]), send_string)
	}
}

func TestNewDTLSServerContext(t *testing.T) {
	log.Print("-- TestNewDTLSServerContext")

	ctx, err := dtls_gnutls.NewDTLSServerContext("ca-cert.pem", "crl.pem", "server-cert.pem", "server-key.pem")
	if err != nil {
		t.Error(err)
	}

	dataCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	sctx, err := ctx.Listen("localhost:5557", dataCh, errCh)
	if err != nil {
		t.Error(err)
	}

	go func() {
		for {
			select {
			case conn := <-dataCh:
				go func() {
					log.Infof("TestNewDTLSServerContext -- connected. client: %s", conn.RemoteAddr().String())

					dtlsConn, ok := conn.(dtls_gnutls.DTLSServerConn)
					if !ok {
						t.Errorf("connection type error, %T", conn)
					}

					if ok && dtlsConn.GetClientCN() != "client.sample.example.com" {
						t.Errorf("CN read error, cn:%s", dtlsConn.GetClientCN())
					}
					data := make([]byte, 1500)
					n, err := conn.Read(data)
					if err != nil {
						t.Errorf("connection read error, %s", err.Error())
					}
					if n != len("test-data") {
						t.Errorf("receive data len error. want: %d, got: %d", len("test-data"), n)
					}
					if string(data[:n]) != "test-data" {
						t.Errorf("receive data error. want: %s, got: %s", "test-data", string(data[:n]))
					}

					conn.Write([]byte("server-send"))
					conn.Close()
				}()
			case err := <-errCh:
				t.Errorf("errch: %s", err)
			}
		}
	}()
	defer sctx.Close()

	// Waiting for the server to complete the boot sequence.
	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)

		go func(wg_ref *sync.WaitGroup, counter int) {
			var clientctx *dtls_gnutls.DTLSCTX
			var clientSession *dtls_gnutls.DTLS_CLIENT_SESSION
			var n int
			var buffer []byte
			var err error

			clientctx, err = dtls_gnutls.NewDTLSClientContext("ca-cert.pem", "client-cert.pem", "client-key.pem")
			if err != nil {
				goto Error
			}
			defer clientctx.Close()

			clientSession, err = clientctx.Connect("localhost:5557")
			if err != nil {
				goto Error
			}
			defer clientSession.Close()
			clientSession.Write([]byte("test-data"))

			buffer = make([]byte, 1500)
			n, _ = clientSession.Read(buffer)
			if string(buffer[:n]) != "server-send" {
				err = errors.New(fmt.Sprintf("receive data error. want: %s, got: %s", "server-send", string(buffer[:n])))
				goto Error
			}

			wg_ref.Done()
			log.Infof("client %d finish.", counter)
			return
		Error:
			wg_ref.Done()
			t.Error(err)
		}(&wg, i)
	}

	log.Infof("wait.")
	wg.Wait()
	log.Infof("done.")
}
