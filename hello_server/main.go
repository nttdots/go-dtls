package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	log "github.com/sirupsen/logrus"
	dtls "github.com/nttdots/go-dtls"
)

func main() {
	abs, _ := filepath.Abs(os.Args[0])
	execDir := filepath.Dir(abs)
	certFile := filepath.Join(execDir, "../../certs/ca-cert.pem")
	serverCertFile := filepath.Join(execDir, "../../certs/server-cert.pem")
	serverKeyFile := filepath.Join(execDir, "../../certs/server-key.pem")
	crlFile := filepath.Join(execDir, "../../certs/crl.pem")

	//dtls.DebuggingON()

	context, err := dtls.NewDTLSServerContext(certFile, crlFile, serverCertFile, serverKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	defer context.Close()
	context.SetLogLevel(9)

	log.Infof("wait for receive.")
	ch := make(chan net.Conn, 10)
	er := make(chan error, 10)
	listener, err := context.Listen("localhost:4646", ch, er)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		select {
		case conn := <-ch:
			go do(conn)
		}
	}

}

func do(conn net.Conn) {
	log.Infof("Test2.Do: connected. channel: %s", conn.RemoteAddr().String())

	buffer := make([]byte, 1500)
	rlen, err := conn.Read(buffer)
	if err != nil {
		log.Print(err)
		return
	}
	log.Infof("Test2.Do: receive %d bytes. channel: %s", rlen, conn.RemoteAddr().String())

	result := []byte(fmt.Sprintf("Hello, '%s'", string(buffer[:rlen])))
	slen, err := conn.Write(result)
	if err != nil {
		log.Print(err)
		return
	}
	log.Infof("Test2.Do: send %d bytes. channel: %s", slen, conn.RemoteAddr().String())
}
