package reload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"warp-mihomo/internal/pool"
)

func TestPrepareKeepsPoolUntilPromote(t *testing.T) {
	C.SetHomeDir(t.TempDir())
	first := mustYAML(t, 0,
		[]deviceSpec{
			{pool.NetworkH3, "warp-front-h3-1", "162.159.198.1", 4443},
			{pool.NetworkH3, "warp-front-h3-2", "162.159.198.2", 8443},
			{pool.NetworkH2, "warp-front-h2-1", "162.159.198.10", 500},
		},
		[]deviceSpec{
			{pool.NetworkH3, "warp-exit-h3-1", "162.159.198.1", 1701},
			{pool.NetworkH2, "warp-exit-h2-1", "162.159.198.11", 8095},
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
	beforeH3Pool := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH3, 0)]
	beforeH2Pool := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH2, 0)]
	if beforeH3Pool == nil || beforeH2Pool == nil {
		t.Fatal("missing initial front pools")
	}
	next := mustYAML(t, 1,
		[]deviceSpec{
			{pool.NetworkH3, "warp-front-h3-g1-1", "162.159.198.1", 4500},
			{pool.NetworkH3, "warp-front-h3-g1-2", "162.159.198.2", 443},
			{pool.NetworkH2, "warp-front-h2-g1-1", "162.159.198.40", 8443},
		},
		[]deviceSpec{
			{pool.NetworkH3, "warp-exit-h3-g1-1", "162.159.198.2", 500},
			{pool.NetworkH2, "warp-exit-h2-g1-1", "162.159.198.41", 4500},
		},
	)
	cfg, restore, err = Prepare(next)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Proxies()[pool.PoolName] != before {
		t.Fatal("prepare replaced the live pool")
	}
	if tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH3, 0)] != beforeH3Pool || tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH2, 0)] != beforeH2Pool {
		t.Fatal("prepare replaced the old front pools")
	}
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH3, 1)]; !ok {
		t.Fatal("new h3 front pool was not staged")
	}
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH2, 1)]; !ok {
		t.Fatal("new h2 front pool was not staged")
	}
	if got := tunnel.Proxies()["warp-exit-h2-g1-1"].Addr(); got != "162.159.198.41:4500" {
		t.Fatalf("staged exit addr %s", got)
	}
	// Verify staged exit proxies are wired to tunnel.Tunnel so dialer-proxy
	// lookup succeeds instead of failing with a nil proxydialer.Tunnel.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, dialErr := tunnel.Proxies()["warp-exit-h3-g1-1"].DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		Host:    "127.0.0.1",
		DstPort: 1,
	})
	cancel()
	if dialErr != nil && strings.Contains(dialErr.Error(), "proxydialer.Tunnel") {
		t.Fatalf("staged exit missing tunnel wiring: %v", dialErr)
	}
	if err := Promote(cfg); err != nil {
		t.Fatal(err)
	}
	restore = nil
	if tunnel.Proxies()[pool.PoolName] == before {
		t.Fatal("promote left the old pool in place")
	}
	if tunnel.Proxies()["warp-exit-h2-1"].Addr() != "162.159.198.11:8095" {
		t.Fatal("old exit was removed while it should stay reachable")
	}
	if tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH3, 0)] != beforeH3Pool || tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH2, 0)] != beforeH2Pool {
		t.Fatal("old front pools were removed while old exits should stay reachable")
	}
	Drop([]string{
		"warp-exit-h3-1", "warp-exit-h2-1",
		"warp-front-h3-1", "warp-front-h3-2", "warp-front-h2-1",
		pool.FrontGroupName(pool.NetworkH3, 0),
		pool.FrontGroupName(pool.NetworkH2, 0),
	})
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH3, 0)]; ok {
		t.Fatal("old h3 front pool survived Drop")
	}
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH2, 0)]; ok {
		t.Fatal("old h2 front pool survived Drop")
	}
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH3, 1)]; !ok {
		t.Fatal("new h3 front pool was removed by Drop")
	}
	if _, ok := tunnel.Proxies()[pool.FrontGroupName(pool.NetworkH2, 1)]; !ok {
		t.Fatal("new h2 front pool was removed by Drop")
	}
	Drop([]string{
		pool.PoolName,
		"warp-exit-h3-g1-1", "warp-exit-h2-g1-1",
		"warp-front-h3-g1-1", "warp-front-h3-g1-2", "warp-front-h2-g1-1",
		pool.FrontGroupName(pool.NetworkH3, 1),
		pool.FrontGroupName(pool.NetworkH2, 1),
	})
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
		[]deviceSpec{
			{pool.NetworkH3, "warp-front-h3-1", "162.159.198.1", 4443},
			{pool.NetworkH2, "warp-front-h2-1", "162.159.198.10", 443},
		},
		[]deviceSpec{
			{pool.NetworkH3, "warp-exit-h3-1", "162.159.198.2", 8443},
			{pool.NetworkH2, "warp-exit-h2-1", "162.159.198.11", 8443},
		},
	))
	close(stop)
	if restore != nil {
		defer restore()
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[pool.PoolName] == nil || cfg.Proxies[pool.FrontGroupName(pool.NetworkH3, 0)] == nil || cfg.Proxies[pool.FrontGroupName(pool.NetworkH2, 0)] == nil {
		t.Fatal("missing pool or front pools")
	}
	if changed.Load() || dialer.DefaultRoutingMark.Load() != mark || !resolver.DisableIPv6 {
		t.Fatal("prepare changed process-global dialer settings")
	}
}

type deviceSpec struct {
	network string
	name    string
	server  string
	port    int
}

func mustYAML(t *testing.T, gen int, fronts, exits []deviceSpec) []byte {
	t.Helper()
	devices := make([]pool.Device, 0, len(fronts)+len(exits))
	for _, f := range fronts {
		devices = append(devices, mustDev(t, pool.RoleFront, f.network, gen, f.name, f.server, f.port))
	}
	for _, e := range exits {
		devices = append(devices, mustDev(t, pool.RoleExit, e.network, gen, e.name, e.server, e.port))
	}
	raw, err := pool.YAML(devices, false)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustDev(t *testing.T, role, network string, gen int, name, server string, port int) pool.Device {
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
		Network:    network,
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

func TestProbeTracksPartialFrontFailureAndAllFail(t *testing.T) {
	tracks := []ProbeTrack{{
		Name:   "h3",
		Fronts: []string{"front-1", "front-2"},
		Exits:  []string{"exit-1", "exit-2"},
	}}

	// One front fails and one front succeeds; first exit fails and second succeeds.
	var probed []string
	err := probeTracksWith(nil, tracks, func(_ *config.Config, name string) error {
		probed = append(probed, name)
		switch name {
		case "front-1", "exit-1":
			return errors.New("timeout")
		default:
			return nil
		}
	})
	if err != nil {
		t.Fatalf("expected partial front failure to pass, got %v", err)
	}
	wantProbed := []string{"front-1", "front-2", "exit-1", "exit-2"}
	if strings.Join(probed, ",") != strings.Join(wantProbed, ",") {
		t.Fatalf("probed = %v, want %v", probed, wantProbed)
	}

	// All fronts fail -> returns first front error without probing exits.
	err = probeTracksWith(nil, tracks, func(_ *config.Config, name string) error {
		if strings.HasPrefix(name, "exit-") {
			t.Fatalf("exit %s should not be probed when all fronts failed", name)
		}
		return errors.New("udp blocked")
	})
	if err == nil || !strings.Contains(err.Error(), "probe h3 front front-1") {
		t.Fatalf("expected first front error, got %v", err)
	}
}
