package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

var (
	messages    = make(chan string, 10)
	consumers   = make(map[net.Conn]struct{})
	consumersMu sync.Mutex
	wg          sync.WaitGroup
)

func createTLSServer(certPath, keyPath, caPath string) (*net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	ln, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to start TLS listener: %w", err)
	}
	return &ln, nil
}

func handlePublisher(conn net.Conn) {
	defer conn.Close()
	defer wg.Done()
	fmt.Println("Handling publisher connection...")
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Publisher connection closed or error:", err)
			return
		}
		message := string(buf[:n])
		fmt.Println("Received from publisher:", message)
		messages <- message
	}
}

func handleConsumer(conn net.Conn) {
	defer conn.Close()
	defer wg.Done()
	fmt.Println("Handling consumer connection...")
	consumersMu.Lock()
	consumers[conn] = struct{}{}
	consumersMu.Unlock()
	defer func() {
		consumersMu.Lock()
		delete(consumers, conn)
		consumersMu.Unlock()
	}()
	for {
		select {
		case msg := <-messages:
			fmt.Println("Sending to consumer:", msg)
			_, err := conn.Write([]byte(msg))
			if err != nil {
				fmt.Println("Failed to send to consumer:", err)
				return
			}
		case <-time.After(30 * time.Second):
			fmt.Println("No messages to send to consumer, timing out.")
			return
		}
	}
}

func broadcastMessages() {
	for {
		msg := <-messages
		fmt.Println("Broadcasting message:", msg)
		consumersMu.Lock()
		for conn := range consumers {
			go func(c net.Conn, m string) {
				_, err := c.Write([]byte(m))
				if err != nil {
					fmt.Println("Error sending message to consumer:", err)
				}
			}(conn, msg)
		}
		consumersMu.Unlock()
	}
}

func main() {
	listener, err := createTLSServer("server-cert.pem", "server-key.pem", "ca-cert.pem")
	if err != nil {
		fmt.Println("Failed to create TLS server:", err)
		return
	}
	defer (*listener).Close()
	fmt.Println("Server started on port 8443")
	go broadcastMessages()
	for {
		conn, err := (*listener).Accept()
		if err != nil {
			fmt.Println("Failed to accept connection:", err)
			continue
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			fmt.Println("Connection is not a TLS connection")
			conn.Close()
			continue
		}
		err = tlsConn.Handshake()
		if err != nil {
			fmt.Println("TLS handshake failed:", err)
			tlsConn.Close()
			continue
		}
		peerCerts := tlsConn.ConnectionState().PeerCertificates
		if len(peerCerts) == 0 {
			fmt.Println("No peer certificates found")
			tlsConn.Close()
			continue
		}
		fmt.Println("Accepted connection from:", peerCerts[0].Subject.CommonName)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			buf := make([]byte, 1024)
			n, err := c.Read(buf)
			if err != nil {
				fmt.Println("Failed to read from connection:", err)
				c.Close()
				return
			}
			clientType := string(buf[:n])
			fmt.Println("Client type:", clientType)
			if clientType == "publisher" {
				wg.Add(1)
				handlePublisher(c)
			} else if clientType == "consumer" {
				wg.Add(1)
				handleConsumer(c)
			} else {
				fmt.Println("Unknown client type")
				c.Close()
			}
		}(tlsConn)
	}
	wg.Wait()
}
