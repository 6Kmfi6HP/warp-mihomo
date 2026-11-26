package warp

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultFallbackRegURL is the browser-style registration endpoint that
// fronts Cloudflare WARP MASQUE enrollment (the service behind
// m2c.pages.dev). It is used when the official API answers 429.
const DefaultFallbackRegURL = "https://usque-register-server.pages.dev/0906?raw=true"

// browserHeaders mimic a real browser tab on the registration frontend.
// The register proxy behind m2c.pages.dev authorizes requests by Origin and
// Referer instead of keys, so a server-side caller must present the
// frontend's own origin the same way the browser does.
var browserHeaders = map[string]string{
	"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Accept":     "*/*",
	"Origin":     "https://m2c.pages.dev",
	"Referer":    "https://m2c.pages.dev/",
}

// fallbackResponse mirrors the JSON body of the browser-side registration
// helper: one GET returns a fully enrolled MASQUE identity.
type fallbackResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Content struct {
		PrivateKey     string `json:"private_key"`
		EndpointPubKey string `json:"endpoint_pub_key"`
		IPv4           string `json:"ipv4"`
		IPv6           string `json:"ipv6"`
	} `json:"content"`
}

// RegisterFallback enrolls one MASQUE device through url, a browser-style
// registration endpoint such as the one powering m2c.pages.dev. The request
// presents the frontend's Origin/Referer because the service authorizes by
// source website rather than by key. name is accepted for call-site parity
// with Register, but the remote service names the device itself.
func RegisterFallback(ctx context.Context, url, name string) (Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Identity{}, err
	}
	for k, v := range browserHeaders {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return Identity{}, err
	}
	var fr fallbackResponse
	if jerr := json.Unmarshal(raw, &fr); jerr != nil {
		return Identity{}, fmt.Errorf("fallback register %s: %s", res.Status, clip(raw))
	}
	if res.StatusCode/100 != 2 {
		return Identity{}, fmt.Errorf("fallback register %s: %s", res.Status, reason(fr.Message, raw))
	}
	if !fr.Success {
		return Identity{}, fmt.Errorf("fallback register: %s", reason(fr.Message, raw))
	}
	if fr.Content.PrivateKey == "" {
		return Identity{}, fmt.Errorf("fallback register: no private key")
	}
	der, err := base64.StdEncoding.DecodeString(fr.Content.PrivateKey)
	if err != nil {
		return Identity{}, fmt.Errorf("fallback private key: %w", err)
	}
	if _, err := x509.ParseECPrivateKey(der); err != nil {
		return Identity{}, fmt.Errorf("fallback private key: %w", err)
	}
	pub, err := pemBody(fr.Content.EndpointPubKey)
	if err != nil {
		return Identity{}, fmt.Errorf("fallback endpoint public key: %w", err)
	}
	ip, err := hostOnly(fr.Content.IPv4)
	if err != nil {
		return Identity{}, fmt.Errorf("fallback ipv4: %w", err)
	}
	ip6, err := hostOnly(fr.Content.IPv6)
	if err != nil {
		return Identity{}, fmt.Errorf("fallback ipv6: %w", err)
	}
	return Identity{
		PrivateKey: fr.Content.PrivateKey,
		PublicKey:  pub,
		IP:         ip,
		IPv6:       ip6,
	}, nil
}

func reason(message string, raw []byte) string {
	if message != "" {
		return message
	}
	return clip(raw)
}
