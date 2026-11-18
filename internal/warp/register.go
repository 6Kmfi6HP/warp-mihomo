// Package warp enrolls a Cloudflare WARP device as a MASQUE identity.
// The registration flow matches worker/src/warp.ts: a curve25519 placeholder
// registration, then a P-256 MASQUE enrollment. Calling it accepts the
// Cloudflare terms of service.
package warp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const api = "https://api.cloudflareclient.com/v0a4471"

var headers = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
}

// Identity is the material mihomo's masque outbound needs. PrivateKey and
// PublicKey are standard base64. PrivateKey is SEC1, which mihomo parses;
// PublicKey is the peer SPKI.
type Identity struct {
	PrivateKey string
	PublicKey  string
	IP         string
	IPv6       string
}

type account struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config *struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Message string `json:"message"`
}

// TOSTimestamp is the timestamp Cloudflare stores when the client accepts the terms.
func TOSTimestamp(now time.Time) string {
	return now.UTC().Format("2006-01-02T15:04:05.000-07:00")
}

// Register enrolls one MASQUE device. name is stored on the Cloudflare account.
func Register(ctx context.Context, name string) (Identity, error) {
	wg := make([]byte, 32)
	serial := make([]byte, 8)
	if _, err := rand.Read(wg); err != nil {
		return Identity{}, err
	}
	if _, err := rand.Read(serial); err != nil {
		return Identity{}, err
	}
	body, err := json.Marshal(map[string]string{
		"key":           base64.StdEncoding.EncodeToString(wg),
		"install_id":    "",
		"fcm_token":     "",
		"tos":           TOSTimestamp(time.Now()),
		"model":         "PC",
		"serial_number": hex.EncodeToString(serial),
		"os_version":    "",
		"key_type":      "curve25519",
		"tunnel_type":   "wireguard",
		"locale":        "en_US",
	})
	if err != nil {
		return Identity{}, err
	}
	acc, err := cf(ctx, http.MethodPost, "/reg", "", body)
	if err != nil {
		return Identity{}, err
	}
	if acc.ID == "" || acc.Token == "" {
		return Identity{}, fmt.Errorf("registration returned no device token")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Identity{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return Identity{}, err
	}
	patch, err := json.Marshal(map[string]string{
		"key":         base64.StdEncoding.EncodeToString(spki),
		"key_type":    "secp256r1",
		"tunnel_type": "masque",
		"name":        name,
	})
	if err != nil {
		return Identity{}, err
	}
	enrolled, err := cf(ctx, http.MethodPatch, "/reg/"+acc.ID, acc.Token, patch)
	if err != nil {
		return Identity{}, err
	}
	if enrolled.Config == nil || len(enrolled.Config.Peers) == 0 || enrolled.Config.Peers[0].PublicKey == "" {
		return Identity{}, fmt.Errorf("enrollment returned no MASQUE peer")
	}
	ip, err := hostOnly(enrolled.Config.Interface.Addresses.V4)
	if err != nil {
		return Identity{}, fmt.Errorf("enrollment v4: %w", err)
	}
	ip6, err := hostOnly(enrolled.Config.Interface.Addresses.V6)
	if err != nil {
		return Identity{}, fmt.Errorf("enrollment v6: %w", err)
	}
	pub, err := pemBody(enrolled.Config.Peers[0].PublicKey)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		PrivateKey: base64.StdEncoding.EncodeToString(sec1),
		PublicKey:  pub,
		IP:         ip,
		IPv6:       ip6,
	}, nil
}

func hostOnly(cidr string) (string, error) {
	if cidr == "" {
		return "", fmt.Errorf("empty address")
	}
	if ip, _, err := net.ParseCIDR(cidr); err == nil {
		return ip.String(), nil
	}
	if net.ParseIP(cidr) == nil {
		return "", fmt.Errorf("bad address %q", cidr)
	}
	return cidr, nil
}

var pemHeader = regexp.MustCompile(`-----BEGIN [^-]+-----|-----END [^-]+-----`)

func pemBody(pem string) (string, error) {
	s := strings.Join(strings.Fields(pemHeader.ReplaceAllString(pem, "")), "")
	if s == "" {
		return "", fmt.Errorf("empty endpoint public key")
	}
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return "", fmt.Errorf("endpoint public key: %w", err)
	}
	return s, nil
}

func cf(ctx context.Context, method, path, token string, body []byte) (account, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, api+path, bytes.NewReader(body))
	if err != nil {
		return account{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return account{}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return account{}, err
	}
	var acc account
	if jerr := json.Unmarshal(raw, &acc); jerr != nil && res.StatusCode/100 != 2 {
		return account{}, fmt.Errorf("cloudflare %s: %s", res.Status, clip(raw))
	}
	if res.StatusCode/100 != 2 {
		reason := acc.Message
		if len(acc.Errors) > 0 && acc.Errors[0].Message != "" {
			reason = acc.Errors[0].Message
		}
		if reason == "" {
			reason = clip(raw)
		}
		return account{}, fmt.Errorf("cloudflare %s: %s", res.Status, reason)
	}
	if err := json.Unmarshal(raw, &acc); err != nil {
		return account{}, fmt.Errorf("cloudflare %s: %w", res.Status, err)
	}
	return acc, nil
}

func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 180 {
		s = s[:180]
	}
	if s == "" {
		return "empty response"
	}
	return s
}
