package pool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor"

	"warp-mihomo/internal/warp"
)

func TestEnsureFillsOnce(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	reg := func(name string) (warp.Identity, error) {
		calls++
		return warp.Identity{
			PrivateKey: "priv-" + name,
			PublicKey:  "pub-" + name,
			IP:         "172.16.0.2",
			IPv6:       "2606:4700:110::" + name,
		}, nil
	}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Ensure(dir, 2, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("enroll calls %d, want 3", calls)
	}
	if got[0].Role != RoleFront || got[0].Name != FrontName {
		t.Fatalf("front %+v", got[0])
	}
	if got[1].Name != "warp-exit-1" || got[2].Name != "warp-exit-2" {
		t.Fatalf("exits %+v", got[1:])
	}
	seen := map[string]bool{}
	for _, d := range got {
		if seen[d.Server] {
			t.Fatalf("duplicate server %s", d.Server)
		}
		seen[d.Server] = true
		if d.Port != 443 {
			t.Fatalf("port %d", d.Port)
		}
	}

	unlock, err = Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Ensure(dir, 2, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("second ensure enrolled again, calls %d", calls)
	}
	if again[0].Server != got[0].Server || again[1].PrivateKey != got[1].PrivateKey {
		t.Fatal("stored identities changed")
	}

	unlock, err = Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	grown, err := Ensure(dir, 3, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 || len(grown) != 4 || grown[3].Name != "warp-exit-3" {
		t.Fatalf("grow calls %d devices %+v", calls, grown)
	}
}

func TestRotateKeepsOldGeneration(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	reg := func(name string) (warp.Identity, error) {
		calls++
		return warp.Identity{
			PrivateKey: "priv-" + name,
			PublicKey:  "pub-" + name,
			IP:         "172.16.0.2",
			IPv6:       "2606:4700:110::1",
		}, nil
	}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	first, err := Ensure(dir, 1, reg)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Rotate(dir, 1, reg)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("calls %d", calls)
	}
	if next[0].Name != "warp-front-g1" || next[1].Name != "warp-exit-g1-1" {
		t.Fatalf("next %+v", next)
	}
	if next[0].Server == first[0].Server || next[1].Server == first[1].Server {
		t.Fatalf("address was not rotated: %s %s", next[0].Server, next[1].Server)
	}
	again, err := Ensure(dir, 1, reg)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Name != next[0].Name || calls != 4 {
		t.Fatalf("ensure re-enrolled after rotate: %+v calls %d", again, calls)
	}
	if !GenerationIdle([]string{first[0].Name, first[1].Name}, nil) {
		t.Fatal("idle generation reported busy")
	}
	if GenerationIdle([]string{first[0].Name, first[1].Name}, [][]string{{"warp-pool", first[1].Name}}) {
		t.Fatal("live exit was treated as idle")
	}
}

func TestEnsureRejectsSecondLock(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := Lock(dir); err == nil {
		t.Fatal("second lock succeeded")
	}
}

func TestYAMLParsesAsMihomo(t *testing.T) {
	devices := []Device{mustDevice(t, RoleFront, FrontName)}
	for _, name := range []string{"warp-exit-1", "warp-exit-2"} {
		devices = append(devices, mustDevice(t, RoleExit, name))
	}
	raw, err := YAML(devices, true)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	C.SetHomeDir(home)
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, raw)
	}
	if !cfg.General.Tun.Enable || !cfg.General.Tun.AutoRoute || !cfg.General.Tun.AutoDetectInterface {
		t.Fatalf("tun %+v", cfg.General.Tun)
	}
	if cfg.General.Tun.Stack != C.TunMips {
		t.Fatalf("stack %s", cfg.General.Tun.Stack)
	}
	if cfg.General.FindProcessMode.String() != "off" {
		t.Fatalf("find process %s", cfg.General.FindProcessMode)
	}
	if !cfg.DNS.Enable || cfg.DNS.EnhancedMode != C.DNSMapping {
		t.Fatalf("dns enable %v mode %s", cfg.DNS.Enable, cfg.DNS.EnhancedMode)
	}
	if len(cfg.DNS.NameServer) != 1 || cfg.DNS.NameServer[0].ProxyName != PoolName {
		t.Fatalf("nameserver %+v", cfg.DNS.NameServer)
	}
	front := cfg.Proxies[FrontName].ProxyInfo()
	if front.DialerProxy != "" {
		t.Fatalf("front dialer %q", front.DialerProxy)
	}
	for _, name := range []string{"warp-exit-1", "warp-exit-2"} {
		info := cfg.Proxies[name].ProxyInfo()
		if info.DialerProxy != FrontName {
			t.Fatalf("%s dialer %q", name, info.DialerProxy)
		}
	}
	group, ok := cfg.Proxies[PoolName]
	if !ok {
		t.Fatal("missing pool group")
	}
	encoded, err := group.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, "warp-exit-1") || !strings.Contains(text, "warp-exit-2") || strings.Contains(text, FrontName) {
		t.Fatalf("group %s", text)
	}
}

func mustDevice(t *testing.T, role, name string) Device {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Device{
		Role:       role,
		Name:       name,
		PrivateKey: base64.StdEncoding.EncodeToString(sec1),
		PublicKey:  base64.StdEncoding.EncodeToString(spki),
		IP:         "172.16.0.2",
		IPv6:       "2606:4700:110::1",
		Server:     "162.159.198.2",
		Port:       443,
	}
}
