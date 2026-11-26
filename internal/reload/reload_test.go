package reload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"warp-mihomo/internal/pool"
)

func TestPrepareKeepsPoolUntilPromote(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	first := mustYAML(t, 0,
		[]deviceSpec{
			{"warp-front-1", "162.159.198.2", 443},
			{"warp-front-2", "162.159.198.4", 500},
		},
		[]deviceSpec{
			{"warp-exit-1", "162.159.198.3", 8095},
		},
	)
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
	beforeFrontPool := tunnel.Proxies()[pool.FrontGroupName(0)]
	if beforeFrontPool == nil {
		t.Fatal("missing initial front pool")
	}
	next := mustYAML(t, 1,
		[]deviceSpec{
			{"warp-front-g1-1", "162.159.198.40", 8443},
			{"warp-front-g1-2", "162.159.198.42", 1701},
		},
		[]deviceSpec{
			{"warp-exit-g1-1", "162.159.198.41", 4500},
		},
	)
	cfg, restore, err = Prepare(next)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Proxies()[pool.PoolName] != before {
		t.Fatal("prepare replaced the live pool")
	}
	if tunnel.Proxies()[pool.FrontGroupName(0)] != beforeFrontPool {
		t.Fatal("prepare replaced the old front pool")
	}
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(1)]; !ok {
		t.Fatal("new front pool was not staged")
	}
	if _, ok := tunnel.Proxies()["warp-front-g1-1"]; !ok {
		t.Fatal("new front was not staged")
	}
	if got := tunnel.Proxies()["warp-exit-g1-1"].Addr(); got != "162.159.198.41:4500" {
		t.Fatalf("staged exit addr %s", got)
	}
	if err := Promote(cfg); err != nil {
		t.Fatal(err)
	}
	restore = nil
	if tunnel.Proxies()[pool.PoolName] == before {
		t.Fatal("promote left the old pool in place")
	}
	if tunnel.Proxies()["warp-exit-1"].Addr() != "162.159.198.3:8095" {
		t.Fatal("old exit was removed while it should stay reachable")
	}
	if tunnel.Proxies()[pool.FrontGroupName(0)] != beforeFrontPool {
		t.Fatal("old front pool was removed while old exit should stay reachable")
	}
	Drop([]string{"warp-exit-1", "warp-front-1", "warp-front-2", pool.FrontGroupName(0)})
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(0)]; ok {
		t.Fatal("old front pool survived Drop")
	}
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(1)]; !ok {
		t.Fatal("new front pool was removed by Drop")
	}
}
func TestPreparePreservesRoutingMark(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	const mark int32 = 0x2023
	oldMark := dialer.DefaultRoutingMark.Load()
	oldIPv6 := resolver.DisableIPv6
	dialer.DefaultRoutingMark.Store(mark)
	resolver.DisableIPv6 = true
	defer func() {
		dialer.DefaultRoutingMark.Store(oldMark)
		resolver.DisableIPv6 = oldIPv6
	}()
	var changed atomic.Bool
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if dialer.DefaultRoutingMark.Load() != mark || !resolver.DisableIPv6 {
				changed.Store(true)
			}
		}
	}()
	cfg, restore, err := Prepare(mustYAML(t, 0,
		[]deviceSpec{{"warp-front-1", "162.159.198.2", 443}},
		[]deviceSpec{{"warp-exit-1", "162.159.198.3", 8443}},
	))
	close(stop)
	if restore != nil {
		defer restore()
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[pool.PoolName] == nil || cfg.Proxies[pool.FrontGroupName(0)] == nil {
		t.Fatal("missing pool or front pool")
	}
	if changed.Load() || dialer.DefaultRoutingMark.Load() != mark || !resolver.DisableIPv6 {
		t.Fatal("prepare changed process-global dialer settings")
	}
}

type deviceSpec struct {
	name   string
	server string
	port   int
}

func mustYAML(t *testing.T, gen int, fronts, exits []deviceSpec) []byte {
	t.Helper()
	devices := make([]pool.Device, 0, len(fronts)+len(exits))
	for _, f := range fronts {
		devices = append(devices, mustDev(t, pool.RoleFront, gen, f.name, f.server, f.port))
	}
	for _, e := range exits {
		devices = append(devices, mustDev(t, pool.RoleExit, gen, e.name, e.server, e.port))
	}
	raw, err := pool.YAML(devices, false)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustDev(t *testing.T, role string, gen int, name, server string, port int) pool.Device {
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
		Generation: gen,
		PrivateKey: base64.StdEncoding.EncodeToString(sec1),
		PublicKey:  base64.StdEncoding.EncodeToString(spki),
		IP:         "172.16.0.2",
		IPv6:       "2606:4700:110::1",
		Server:     server,
		Port:       port,
	}
}
