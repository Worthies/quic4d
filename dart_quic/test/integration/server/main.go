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
// mTLS config, for dart_quic's integration test. Reads newline-
// delimited lines (matching commander's wire framing) from the
// client's first bidi stream in a loop, echoing each back with a
// prefix, until the stream is closed by the peer or an optional
// message-count limit (3rd CLI arg, default: unlimited until EOF) is
// reached, then exits.
func main() {
	certDir := os.Args[1]
	addr := os.Args[2]
	maxMessages := -1 // unlimited -- read until the client closes the stream
	if len(os.Args) > 3 {
		if n, err := fmt.Sscanf(os.Args[3], "%d", &maxMessages); err != nil || n != 1 {
			log.Fatalf("invalid max-messages argument: %v", os.Args[3])
		}
	}

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
	count := 0
	for maxMessages < 0 || count < maxMessages {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("read ended: %v", err)
			break
		}
		log.Printf("received: %q", line)
		count++

		reply := "echo:" + line
		if _, err := stream.Write([]byte(reply)); err != nil {
			log.Fatalf("write: %v", err)
		}
		log.Printf("sent: %q", reply)
	}

	time.Sleep(200 * time.Millisecond)
	stream.Close()
	conn.CloseWithError(0, "done")
}
