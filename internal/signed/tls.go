package signed

import (
	"context"
	"crypto/x509"
	"errors"
	"net"

	utls "github.com/mrqs001/vpngate/internal/third_party/utls"
)

// DialFunc opens a TCP connection; vpngate passes its tunnel-bound dialer.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type tlsConfig struct {
	roots    *x509.CertPool // nil: system roots
	insecure bool
	h2       bool // offer h2 in ALPN; false offers only http/1.1
	cache    utls.ClientSessionCache
}

// helloSpec returns a fresh ClientHello spec for one connection. A
// pre_shared_key extension is appended as Chrome does; uTLS leaves it out of
// fresh handshakes (OmitEmptyPsk) and fills it when resuming.
func helloSpec(p *Profile, h2 bool) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(p.HelloID)
	if err != nil {
		return spec, err
	}
	if !h2 {
		for _, e := range spec.Extensions {
			if a, ok := e.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = []string{"http/1.1"}
			}
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	return spec, nil
}

// dialTLS dials addr and performs the profile's TLS handshake.
func dialTLS(ctx context.Context, dial DialFunc, addr, serverName string, p *Profile, c *tlsConfig) (*utls.UConn, error) {
	spec, err := helloSpec(p, c.h2)
	if err != nil {
		return nil, err
	}
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{ServerName: serverName, RootCAs: c.roots, InsecureSkipVerify: c.insecure,
		MinVersion: utls.VersionTLS12, OmitEmptyPsk: true}
	if c.cache != nil {
		cfg.ClientSessionCache = c.cache
		cfg.PreferSkipResumptionOnNilExtension = true
	} else {
		cfg.SessionTicketsDisabled = true
	}
	conn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err = conn.ApplyPreset(&spec); err == nil {
		err = conn.HandshakeContext(ctx)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// IsCertificateError reports whether err is a certificate verification
// failure, which retrying on another tunnel cannot fix.
func IsCertificateError(err error) bool {
	var cv *utls.CertificateVerificationError
	var host x509.HostnameError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &cv) || errors.As(err, &host) || errors.As(err, &authority) || errors.As(err, &invalid)
}
