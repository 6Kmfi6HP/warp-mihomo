package warp

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestTOSTimestampUsesOffset(t *testing.T) {
	got := TOSTimestamp(time.Date(2026, 11, 18, 1, 2, 3, 4_000_000, time.FixedZone("X", 3600)))
	if got != "2026-11-18T00:02:03.004+00:00" {
		t.Fatalf("timestamp %s", got)
	}
	if strings.Contains(got, "Z") {
		t.Fatalf("timestamp must not use Z: %s", got)
	}
}

func TestPemBody(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte("warp-peer"))
	got, err := pemBody("-----BEGIN PUBLIC KEY-----\n" + raw + "\n-----END PUBLIC KEY-----\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != raw {
		t.Fatalf("got %s", got)
	}
	got, err = pemBody(raw)
	if err != nil || got != raw {
		t.Fatalf("bare key: %s %v", got, err)
	}
	if _, err := pemBody("-----BEGIN PUBLIC KEY-----\n-----\n"); err == nil {
		t.Fatal("empty body accepted")
	}
}

func TestHostOnly(t *testing.T) {
	got, err := hostOnly("172.16.0.2/32")
	if err != nil || got != "172.16.0.2" {
		t.Fatalf("%s %v", got, err)
	}
	got, err = hostOnly("2606:4700:110::1/128")
	if err != nil || got != "2606:4700:110::1" {
		t.Fatalf("%s %v", got, err)
	}
}
