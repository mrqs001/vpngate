// A local-only TLS/DNS origin for privileged integration tests and benchmarks.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
)

func main() {
	dir := flag.String("dir", "", "certificate directory")
	address := flag.String("ip", "10.253.66.2", "fixture IP")
	generate := flag.Bool("generate", false, "only create fixture certificate")
	delay := flag.Int("delay-ms", 0, "response delay for WAN-like concurrency")
	size := flag.Int("bytes", 40<<10, "response bytes (1 to 8 MiB)")
	flag.Parse()
	if *dir == "" {
		panic("--dir required")
	}
	certPath, keyPath := filepath.Join(*dir, "cert.pem"), filepath.Join(*dir, "key.pem")
	if *generate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			panic(err)
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "vpngate test fixture"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"fixture.test"},
			IPAddresses: []net.IP{net.ParseIP(*address), net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: false, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			panic(err)
		}
		if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
			panic(err)
		}
		if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
			panic(err)
		}
		return
	}
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.ParseIP(*address)})
			}
		}
		_ = w.WriteMsg(m)
	})
	for _, network := range []string{"udp", "tcp"} {
		go func(network string) {
			if err := (&dns.Server{Addr: net.JoinHostPort(*address, "53"), Net: network}).ListenAndServe(); err != nil {
				panic(err)
			}
		}(network)
	}
	if *size < 1 || *size > 8<<20 {
		panic("--bytes outside supported range")
	}
	pattern := []byte("vpngate-fixture!")
	payload := bytes.Repeat(pattern, (*size+len(pattern)-1)/len(pattern))[:*size] // No disk IO.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(*delay) * time.Millisecond)
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	})
	go func() {
		if err := http.ListenAndServe(":18080", handler); err != nil {
			panic(err)
		}
	}()
	server := &http.Server{Addr: ":18443", Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 90 * time.Second}
	if err := server.ListenAndServeTLS(certPath, keyPath); err != nil {
		panic(err)
	}
}
