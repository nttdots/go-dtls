package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	log "github.com/sirupsen/logrus"
	dtls "github.com/nttdots/go-dtls"
)

// dtls client
func main() {
	abs, _ := filepath.Abs(os.Args[0])
	execDir := filepath.Dir(abs)
	certFile := filepath.Join(execDir, "../../certs/ca-cert.pem")
	clientCertFile := filepath.Join(execDir, "../../certs/client-cert.pem")
	clientKeyFile := filepath.Join(execDir, "../../certs/client-key.pem")

	context, err := dtls.NewDTLSClientContext(certFile, clientCertFile, clientKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	defer context.Close()
	context.SetLogLevel(9)

	var wg sync.WaitGroup
	for i := 0; i < 1; i++ {
		wg.Add(1)
		go sendMessage(&wg, context, i)
	}
	//time.Sleep(1)
	//wg.Add(1)
	//sendMessage(&wg, context, 1)

	log.Infof("remain routine: %d", runtime.NumGoroutine())
	wg.Wait()
}

func sendMessage(wg *sync.WaitGroup, context *dtls.DTLSCTX, id int) {
	defer func() {
		log.Infof("done. id: %d", id)
		wg.Done()
	}()

	data := fmt.Sprintf("dtls client %d", id)

	conn, err := context.Connect("127.0.0.1:4646")
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("connected. conn: %+v", conn)
	_, err = conn.Write([]byte(data))
	if err != nil {
		log.Errorf("error %+v", err)
	}

	buffer := make([]byte, 1500)
	size, err := conn.Read(buffer)
	if err != nil {
		log.Errorf("error %+v", err)
	}

	log.Infof("received message: %s", string(buffer[:size]))
	conn.Close()
}
