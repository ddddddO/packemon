package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
)

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func main() {
	log.Println("start https server")

	cert, err := tls.LoadX509KeyPair("./my-tls.com+2.pem", "./my-tls.com+2-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	w := os.Stdout
	// https://pkg.go.dev/crypto/tls#Config
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		Rand:         zeroSource{}, // for example only; don't do this.
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		//CurvePreferences: []tls.CurveID{tls.X25519},
		KeyLogWriter: w,
	}
	tlsListener, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer tlsListener.Close()

	handler := &Handler{}
	log.Fatalln(http.Serve(tlsListener, handler))
}

type Handler struct{}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("passive!")
	fmt.Fprintf(w, "Hellll tls")
}
