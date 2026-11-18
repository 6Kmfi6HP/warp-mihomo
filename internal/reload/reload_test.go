package reload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"warp-mihomo/internal/pool"
)

func TestPrepareKeepsPoolUntilPromote(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	first := mustYAML(t, "warp-front", "162.159.198.2", "warp-exit-1", "162.159.198.3")
	cfg, restore, err := Prepare(first)
	if err != nil {
		t.Fatal(err)
	}
	if restore != nil {
		defer restore()
	}
	if err := Promote(cfg); err != nil {
		t.Fatal(err)
	}
	before := tunnel.Proxies()[pool.PoolName]
	next := mustYAML(t, "warp-front-g1", "162.159.198.40", "warp-exit-g1-1", "162.159.198.41")
	cfg, restore, err = Prepare(next)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Proxies()[pool.PoolName] != before {
		t.Fatal("prepare replaced the live pool")
	}
	if _, ok := tunnel.Proxies()["warp-front-g1"]; !ok {
		t.Fatal("new front was not staged")
	}
	if got := tunnel.Proxies()["warp-exit-g1-1"].Addr(); got != "162.159.198.41:443" {
		t.Fatalf("staged exit addr %s", got)
	}
	if err := Promote(cfg); err != nil {
		t.Fatal(err)
	}
	restore = nil
	if tunnel.Proxies()[pool.PoolName] == before {
		t.Fatal("promote left the old pool in place")
	}
	if tunnel.Proxies()["warp-exit-1"].Addr() != "162.159.198.3:443" {
		t.Fatal("old exit was removed while it should stay reachable")
	}
}

func mustYAML(t *testing.T, front, frontServer, exit, exitServer string) []byte {
	t.Helper()
	devices := []pool.Device{
		mustDev(t, pool.RoleFront, front, frontServer),
		mustDev(t, pool.RoleExit, exit, exitServer),
	}
	raw, err := pool.YAML(devices, false)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustDev(t *testing.T, role, name, server string) pool.Device {
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
	return pool.Device{
		Role:       role,
		Name:       name,
		PrivateKey: base64.StdEncoding.EncodeToString(sec1),
		PublicKey:  base64.StdEncoding.EncodeToString(spki),
		IP:         "172.16.0.2",
		IPv6:       "2606:4700:110::1",
		Server:     server,
		Port:       443,
	}
}
