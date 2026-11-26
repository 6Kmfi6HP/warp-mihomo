package warp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func fallbackBody(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pub := "-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(spki) + "\n-----END PUBLIC KEY-----\n"
	return []byte(fmt.Sprintf(`{"success":true,"content":{"private_key":%q,"endpoint_pub_key":%q,"ipv4":"172.16.0.2/32","ipv6":"2606:4700:110::1/128"},"id":"x.json"}`,
		base64.StdEncoding.EncodeToString(sec1), pub))
}

func TestRegisterFallbackMapsIdentity(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write(fallbackBody(t))
	}))
	defer srv.Close()
	id, err := RegisterFallback(context.Background(), srv.URL, "dev-1")
	if err != nil {
		t.Fatalf("RegisterFallback: %v", err)
	}
	if id.IP != "172.16.0.2" || id.IPv6 != "2606:4700:110::1" {
		t.Fatalf("addresses = %q, %q", id.IP, id.IPv6)
	}
	if !strings.HasPrefix(id.PrivateKey, "MH") {
		t.Fatalf("private key %q is not base64 SEC1", id.PrivateKey)
	}
	if id.PublicKey == "" || strings.ContainsAny(id.PublicKey, "-\n ") {
		t.Fatalf("public key not stripped of PEM wrapper: %q", id.PublicKey)
	}
	if _, err := base64.StdEncoding.DecodeString(id.PublicKey); err != nil {
		t.Fatalf("public key not base64: %v", err)
	}
	// The request must look like a browser tab on the authorized frontend.
	if got.Get("Origin") != "https://m2c.pages.dev" {
		t.Fatalf("Origin = %q", got.Get("Origin"))
	}
	if got.Get("Referer") != "https://m2c.pages.dev/" {
		t.Fatalf("Referer = %q", got.Get("Referer"))
	}
	if !strings.Contains(got.Get("User-Agent"), "Mozilla/5.0") {
		t.Fatalf("User-Agent = %q", got.Get("User-Agent"))
	}
}

func TestRegisterFallbackForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"code":"forbidden","message":"请通过 masque.pages.dev 等授权网站访问"}`))
	}))
	defer srv.Close()
	_, err := RegisterFallback(context.Background(), srv.URL, "dev-1")
	if err == nil || !strings.Contains(err.Error(), "请通过 masque.pages.dev 等授权网站访问") {
		t.Fatalf("err = %v, want frontend message", err)
	}
}

func TestRegisterFallbackHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream unavailable"))
	}))
	defer srv.Close()
	_, err := RegisterFallback(context.Background(), srv.URL, "dev-1")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v, want status 502", err)
	}
}

func TestRegisterFallbackBadKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"content":{"private_key":"not-base64!!","endpoint_pub_key":"x","ipv4":"172.16.0.2","ipv6":"2606:4700:110::1"}}`))
	}))
	defer srv.Close()
	_, err := RegisterFallback(context.Background(), srv.URL, "dev-1")
	if err == nil || !strings.Contains(err.Error(), "fallback private key") {
		t.Fatalf("err = %v, want private key error", err)
	}
}

func TestRegisterFallbackLive(t *testing.T) {
	if os.Getenv("WARP_LIVE_FALLBACK") == "" {
		t.Skip("set WARP_LIVE_FALLBACK=1 to register a real device through the fallback endpoint")
	}
	id, err := RegisterFallback(context.Background(), DefaultFallbackRegURL, "live-check")
	if err != nil {
		t.Fatalf("live fallback: %v", err)
	}
	raw, _ := json.Marshal(map[string]string{"ip": id.IP, "ipv6": id.IPv6})
	t.Logf("live fallback identity: %s pub-key-len=%d", raw, len(id.PublicKey))
}
