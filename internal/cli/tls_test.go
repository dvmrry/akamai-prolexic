package cli

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// tlsAPI is an API behind TLS signed by a CA no system trusts (as a
// TLS-inspecting proxy's is), and a PEM bundle holding that CA.
func tlsAPI(t *testing.T) (Env, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	vars := map[string]string{
		"AKAMAI_HOST":          strings.TrimPrefix(srv.URL, "https://"),
		"AKAMAI_CLIENT_TOKEN":  "akab-client-token-xxx-xxxxxxxxxxxxxxxx",
		"AKAMAI_CLIENT_SECRET": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
		"AKAMAI_ACCESS_TOKEN":  "akab-access-token-xxx-xxxxxxxxxxxxxxxx",
	}
	return Env{Getenv: func(k string) string { return vars[k] }, Home: t.TempDir()}, bundle
}

func TestCABundleTrustsADeclaredCA(t *testing.T) {
	env, bundle := tlsAPI(t)
	if r := runCLI(t, env, "aliases", "list"); r.code != exitCode(apperr.Upstream) {
		t.Errorf("without the bundle: exit %d, want 5 (certificate refused): %s", r.code, r.stderr)
	}
	if r := runCLI(t, env, "aliases", "list", "--ca-bundle", bundle); r.code != 0 {
		t.Errorf("with the bundle: exit %d: %s", r.code, r.stderr)
	}
	r := runCLI(t, env, "doctor", "--ca-bundle", bundle, "--format", "text")
	if r.code != 0 || !strings.Contains(r.stdout, "tls: system roots plus 1 certificates from the CA bundle") {
		t.Errorf("doctor: exit %d:\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestAnUnusableCABundleIsAnError(t *testing.T) {
	env, _ := tlsAPI(t)
	empty := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(empty, []byte("not a certificate\n"), 0o600)
	for name, path := range map[string]string{"no certificate": empty, "missing": filepath.Join(t.TempDir(), "nope.pem")} {
		for _, args := range [][]string{{"aliases", "list"}, {"doctor"}} {
			if r := runCLI(t, env, append(args, "--ca-bundle", path)...); r.code != exitCode(apperr.Usage) {
				t.Errorf("%s, %v: exit %d: %s", name, args, r.code, r.stderr)
			}
		}
	}
}

func TestAnUntrustedCertificateSaysWhy(t *testing.T) {
	env, _ := tlsAPI(t)
	r := runCLI(t, env, "aliases", "list")
	if !strings.Contains(r.stderr, "certificate isn't trusted") || !strings.Contains(r.stderr, "CA bundle") {
		t.Errorf("stderr = %s", r.stderr)
	}
}
