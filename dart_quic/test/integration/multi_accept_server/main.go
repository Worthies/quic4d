package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// Dedicated echo server for reconnect_after_abrupt_death_test.dart --
// unlike test/integration/server/main.go (which accepts exactly ONE
// connection for its whole process lifetime), this one loops on
// Accept() so a test can open a second connection to the same
// listener, exactly like commander reconnecting to the same real
// server address after an abrupt local network death.
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

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("accept ended: %v", err)
			return
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn *quic.Conn) {
	log.Printf("accepted connection from %s", conn.RemoteAddr())
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("accept stream from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer stream.Close()

	reader := bufio.NewReader(stream)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("read ended for %s: %v", conn.RemoteAddr(), err)
			return
		}
		trimmed := strings.TrimSpace(line)
		var reply string
		if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
			reply = line
		} else {
			reply = "echo:" + line
		}
		if _, err := stream.Write([]byte(reply)); err != nil {
			log.Printf("write to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}
