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

// Minimal quic-go server mirroring leaf's server/quic_visitor.go ALPN +
// mTLS config, for dart_quic's and commander's integration tests. Reads
// newline-delimited lines (matching commander's wire framing) from the
// client's first bidi stream in a loop, echoing each back, until the
// stream is closed by the peer or an optional message-count limit (3rd
// CLI arg, -1/absent = unlimited until EOF) is reached, then exits.
//
// Echo behavior per line:
//   - a line that is valid JSON ('{'...'}') is echoed back VERBATIM, so a
//     client exercising a real commander-style JSON message loop sees the
//     same shapes it would from leaf's server model layer;
//   - any other line gets the "echo:" prefix (dart_quic's own interop
//     tests assert on that prefix).
//
// Optional 4th CLI arg "-welcome": right after accepting the stream,
// write a leaf-style welcome line first ({"type":"welcome",...}), the
// way server/quic_visitor.go's accept path does -- needed by
// commander's QuicClient e2e test, which keys its connected/visitorName
// state off that message. dart_quic's own tests do not pass this flag
// (they assert the FIRST received chunk is their echo).
func main() {
	certDir := os.Args[1]
	addr := os.Args[2]
	maxMessages := -1 // unlimited -- read until the client closes the stream
	if len(os.Args) > 3 && os.Args[3] != "-welcome" {
		if n, err := fmt.Sscanf(os.Args[3], "%d", &maxMessages); err != nil || n != 1 {
			log.Fatalf("invalid max-messages argument: %v", os.Args[3])
		}
	}
	sendWelcome := false
	for _, arg := range os.Args[3:] {
		if arg == "-welcome" {
			sendWelcome = true
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

	if sendWelcome {
		welcome := `{"type":"welcome","visitor_name":"e2e-test-user","visitors":[]}` + "\n"
		if _, err := stream.Write([]byte(welcome)); err != nil {
			log.Fatalf("write welcome: %v", err)
		}
		log.Printf("sent welcome")
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

		trimmed := strings.TrimSpace(line)
		var reply string
		if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
			reply = line // valid-JSON-looking line: echo verbatim
		} else {
			reply = "echo:" + line
		}
		if _, err := stream.Write([]byte(reply)); err != nil {
			log.Fatalf("write: %v", err)
		}
		log.Printf("sent: %q", reply)
	}

	time.Sleep(200 * time.Millisecond)
	stream.Close()
	conn.CloseWithError(0, "done")
}
