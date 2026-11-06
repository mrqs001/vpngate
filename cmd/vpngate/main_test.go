package main

import (
	"crypto/x509"
	"os"
	"os/exec"
	"testing"
)

func TestHelpAndVersionAreSuccessful(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"version"}, {"run", "--help"}} {
		if e := run(args); e != nil {
			t.Fatal(e)
		}
	}
}

func TestControlNameAndRateValidation(t *testing.T) {
	for _, args := range [][]string{{"status", "--name", "../another"}, {"limit", "--name", "default"}, {"limit", "--mbps", "-1"}, {"run", "unexpected"}} {
		if e := run(args); e == nil {
			t.Fatal("invalid command accepted")
		}
	}
}

func TestBundledRootsWithoutSystemCertificates(t *testing.T) {
	if os.Getenv("VPNGATE_TEST_ROOTS") == "1" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil || len(pool.Subjects()) < 100 {
			t.Fatal("bundled trust roots unavailable", err)
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestBundledRootsWithoutSystemCertificates$")
	cmd.Env = []string{"VPNGATE_TEST_ROOTS=1", "SSL_CERT_FILE=/nonexistent/vpngate-ca", "SSL_CERT_DIR=/nonexistent/vpngate-cas", "PATH=/nonexistent"}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rootless trust fixture: %v %s", err, output)
	}
}
