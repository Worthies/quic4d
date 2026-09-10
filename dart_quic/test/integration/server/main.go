package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

// Minimal quic-go server mirroring leaf's server/quic_visitor.go ALPN +
// mTLS config, for dart_quic's integration test. Reads one line
// (newline-delimited, matching commander's wire framing) from the
// client's first bidi stream, echoes it back with a prefix, then exits
// after handling one connection.
func main() {
	certDir := os.Args[1]
	addr := os.Args[2]

	caCert, err := os.ReadFile(certDir + "/ca.crt")
	if err != nil {
		log.Fatalf("read ca.crt: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatal("failed to parse ca.crt")
	}

	serverCert, err := tls.LoadX509KeyPair(certDir+"/server.crt", certDir+"/server.key")
	if err != nil {
		log.Fatalf("load server cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"leaf-commander"},
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}

	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Println("READY")

	conn, err := listener.Accept(context.Background())
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	log.Printf("accepted connection from %s", conn.RemoteAddr())

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Fatalf("accept stream: %v", err)
	}

	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	log.Printf("received: %q", line)

	reply := "echo:" + line
	if _, err := stream.Write([]byte(reply)); err != nil {
		log.Fatalf("write: %v", err)
	}
	log.Printf("sent: %q", reply)

	time.Sleep(200 * time.Millisecond)
	stream.Close()
	conn.CloseWithError(0, "done")
}
