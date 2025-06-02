package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

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

func isVictimServerFinished(l int) bool {
	switch *victim {
	case "shadowtls":
		return l == 57 || l == 73
	case "reality":
		return l == 53 || l == 69
	default:
		return false
	}
}

func isClientFinishedLen(l int) bool {
	return l == 53 || l == 69
}

type upstreamScanner struct {
	io.Reader
	ticketsLens []int

	buf            bytes.Buffer
	status         int
	finishedStatus int
	clientFinished *atomic.Bool
}

func (s *upstreamScanner) Read(p []byte) (n int, err error) {
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
	if s.status == s.finishedStatus {
		return n, nil
	}
	p = p[:n]
	for len(p) > 0 {
		recordLen := int(p[3])<<8 + int(p[4])
		switch {
		case isVictimServerFinished(recordLen):
			s.status++
		case s.status == 0 && s.clientFinished.Load():
			s.status++
			fallthrough
		case s.status > 0 && s.status < s.finishedStatus:
			dataLen := recordLen - 17 // 1 byte record type + 16 bytes AEAD tag
			expectedLen := s.ticketsLens[s.status-1]
			if dataLen != expectedLen {
				// In case of Cloudflare, two tickets are batched in one record.
				if dataLen != expectedLen*len(s.ticketsLens) {
					fmt.Println("TLS camouflage connection detected")
				}
				s.status = s.finishedStatus
				return n, nil
			}
			s.status++
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

type downstreamScanner struct {
	io.Reader
	clientFinished *atomic.Bool

	buf bytes.Buffer
}

func (s *downstreamScanner) Read(p []byte) (n int, err error) {
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
	if s.clientFinished.Load() {
		return n, nil
	}
	p = p[:n]
	for len(p) > 0 {
		recordLen := int(p[3])<<8 + int(p[4])
		if isClientFinishedLen(recordLen) {
			s.clientFinished.CompareAndSwap(false, true)
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

func scan(conn net.Conn, upstream net.Conn, rawCH []byte, ticketsLens []int) error {
	var clientFinished atomic.Bool
	var upstreamReader io.Reader = upstream
	if len(ticketsLens) > 0 {
		upstreamReader = &upstreamScanner{
			Reader:         upstream,
			ticketsLens:    ticketsLens,
			finishedStatus: len(ticketsLens) + 1,
			clientFinished: &clientFinished,
		}
	} else {
		fmt.Println("No session tickets found, unable to determine victim protocol")
	}

	// Replay the ClientHello to the upstream server
	_, err := upstream.Write(rawCH)
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		io.Copy(conn, upstreamReader)
	}()

	go func() {
		defer wg.Done()
		io.Copy(upstream, &downstreamScanner{
			Reader:         conn,
			clientFinished: &clientFinished,
		})
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

	clientHello := tls.UnmarshalClientHello(append([]byte{}, payload...))
	probeConn, err := net.Dial("tcp", *remote)
	if err != nil {
		return err
	}
	uconn := tls.UClient(probeConn, &tls.Config{
		ServerName:         clientHello.ServerName,
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

	upstream, err := net.Dial("tcp", *remote)
	if err != nil {
		return err
	}
	fmt.Println("Starting scan...")
	if err := scan(conn, upstream, clientHelloRecord, ticketsLens); err != nil {
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
