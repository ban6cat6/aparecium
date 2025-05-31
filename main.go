package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/davecgh/go-spew/spew"
	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	addr   = flag.String("addr", ":10444", "tcp proxy address")
	remote = flag.String("remote", "127.0.0.1:10443", "tls camouflage server address")
	victim = flag.String("victim", "reality", "victim protocol: shadowtls or reality")
)

const (
	recordHeaderLen = 5
)

func isVictimServerFinishedLen(l int) bool {
	switch *victim {
	case "shadowtls":
		return l == 57 || l == 73
	case "reality":
		return l == 53 || l == 69
	default:
		return false
	}
}

const (
	_ = iota
	statusWaitingTicket0
	_
	statusFinished
)

type scanner struct {
	io.Reader
	ticketsLens []int

	buf    bytes.Buffer
	status int
}

func (s *scanner) Read(p []byte) (n int, err error) {
	// Consume the incomplete record from the buffer first.
	// We need to make sure we are reading at the record boundary.
	if s.buf.Len() > 0 {
		n, _ = s.buf.Read(p)
		return n, nil
	}
	n, err = s.Reader.Read(p)
	if err != nil {
		return n, err
	}
	if s.status == statusFinished {
		return n, nil
	}
	p = p[:n]
	for len(p) > 0 {
		recordLen := int(p[3])<<8 + int(p[4])
		switch {
		case isVictimServerFinishedLen(recordLen):
			s.status = statusWaitingTicket0
		case s.status > 0 && s.status < statusFinished:
			ticketLen := recordLen - 17 // 1 byte record type + 16 bytes AEAD tag
			if s.ticketsLens[0] != ticketLen {
				fmt.Println("TLS camouflage connection detected")
				s.status = statusFinished
			} else {
				s.status++
			}
		case s.status == statusFinished:
			return n, nil
		}
		if l := recordHeaderLen + recordLen; l > len(p) {
			need := make([]byte, l-len(p))
			_, _ = io.ReadFull(s.Reader, need)
			// Save the remaining bytes in the buffer, yield them in the following Read call
			s.buf.Write(need)
			return n, nil
		} else {
			p = p[l:]
		}
	}

	return n, nil
}

func getTicketsLens(uconn *tls.UConn) ([]int, error) {
	connState := uconn.ConnectionState()
	proto := connState.NegotiatedProtocol
	switch proto {
	case "h2":
		_, err := io.WriteString(uconn, http2.ClientPreface)
		if err != nil {
			return nil, err
		}
	default:
		req, err := http.NewRequest(http.MethodGet, "https://"+connState.ServerName, nil)
		if err != nil {
			return nil, err
		}
		err = req.Write(uconn)
		if err != nil {
			return nil, err
		}
	}
	_, err := uconn.Read(make([]byte, 1))
	if err != nil {
		return nil, err
	}

	return uconn.ConnectionState().SessionTicketsLens, nil
}

func scan(conn net.Conn, rawCH []byte, ticketsLens []int) error {
	upstream, err := net.Dial("tcp", *remote)
	if err != nil {
		return err
	}
	// Replay the ClientHello to the upstream server
	_, err = upstream.Write(rawCH)
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		io.Copy(conn, &scanner{
			Reader:      upstream,
			ticketsLens: ticketsLens,
		})
	}()

	go func() {
		defer wg.Done()
		io.Copy(upstream, conn)
	}()

	return nil
}

func handle(conn net.Conn) error {
	var hdr [5]byte
	_, err := io.ReadFull(conn, hdr[:])
	if err != nil {
		return err
	}

	l := int(hdr[3])<<8 + int(hdr[4])
	payload := make([]byte, l)
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return err
	}

	clientHelloRecord := append([]byte{}, hdr[:]...)
	clientHelloRecord = append(clientHelloRecord, payload...)
	fp := tls.Fingerprinter{
		AllowBluntMimicry: true,
	}
	chSpec, err := fp.FingerprintClientHello(clientHelloRecord)
	if err != nil {
		return err
	}

	probeConn, err := net.Dial("tcp", *remote)
	if err != nil {
		return err
	}
	uconn := tls.UClient(probeConn, &tls.Config{
		InsecureSkipVerify: true,
	}, tls.HelloCustom)
	if err := uconn.ApplyPreset(chSpec); err != nil {
		return err
	}
	if err := uconn.Handshake(); err != nil {
		return err
	}
	ticketsLens, err := getTicketsLens(uconn)
	if err != nil {
		return err
	}

	if len(ticketsLens) == 0 {
		fmt.Println("No session tickets found, unable to determine victim protocol")
		return nil
	}

	fmt.Println("Starting scan...")
	if err := scan(conn, clientHelloRecord, ticketsLens); err != nil {
		spew.Dump(err)
	}
	return nil
}

func main() {
	flag.Parse()
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			spew.Dump(err)
		}

		go func() {
			if err := handle(conn); err != nil {
				spew.Dump(err)
			}
		}()
	}
}
