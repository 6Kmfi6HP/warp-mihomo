package pool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/netip"
	"slices"
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
	seenPorts := map[int]bool{}
	for _, d := range got {
		if seen[d.Server] {
			t.Fatalf("duplicate server %s", d.Server)
		}
		seen[d.Server] = true
		if !slices.Contains(masquePorts, d.Port) {
			t.Fatalf("unsupported port %d", d.Port)
		}
		if seenPorts[d.Port] {
			t.Fatalf("duplicate port %d", d.Port)
		}
		seenPorts[d.Port] = true
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
	if grown[3].Port == got[0].Port || grown[3].Port == got[1].Port || grown[3].Port == got[2].Port {
		t.Fatalf("grown exit reused port %d in %+v", grown[3].Port, grown)
	}
}

func TestDistinctPortsAndOverflowBalance(t *testing.T) {
	dir := t.TempDir()
	reg := func(name string) (warp.Identity, error) {
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
	defer unlock()

	// 1 front + 6 exits = 7 devices: every node gets a unique supported port.
	devs, err := Ensure(dir, 6, reg)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, d := range devs {
		if !slices.Contains(masquePorts, d.Port) {
			t.Fatalf("device %s got unsupported port %d", d.Name, d.Port)
		}
		if seen[d.Port] {
			t.Fatalf("duplicate port %d across %+v", d.Port, devs)
		}
		seen[d.Port] = true
	}

	// Growing past len(masquePorts) stays balanced instead of failing.
	more, err := Ensure(dir, 8, reg)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[int]int{}
	for _, d := range more {
		counts[d.Port]++
	}
	for _, p := range masquePorts {
		if counts[p] < 1 || counts[p] > 2 {
			t.Fatalf("unbalanced port %d count %d in %+v", p, counts[p], counts)
		}
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
	rotatedPorts := map[int]bool{first[0].Port: true, first[1].Port: true}
	for _, d := range next {
		if !slices.Contains(masquePorts, d.Port) {
			t.Fatalf("rotated device %s got unsupported port %d", d.Name, d.Port)
		}
		if rotatedPorts[d.Port] {
			t.Fatalf("rotated device %s reused port %d across generations", d.Name, d.Port)
		}
		rotatedPorts[d.Port] = true
	}
	pending, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if activeGeneration(pending) != first[0].Generation {
		t.Fatalf("unprobed generation %d became active", activeGeneration(pending))
	}
	recovered, err := Ensure(dir, 1, reg)
	if err != nil {
		t.Fatal(err)
	}
	if recovered[0].Name != first[0].Name || calls != 4 {
		t.Fatalf("restart kept the unprobed generation: %+v calls %d", recovered, calls)
	}
	next, err = Rotate(dir, 1, reg)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 6 {
		t.Fatalf("calls %d", calls)
	}
	if err := Activate(dir, next[0].Generation); err != nil {
		t.Fatal(err)
	}
	again, err := Ensure(dir, 1, reg)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Name != next[0].Name || calls != 6 {
		t.Fatalf("ensure re-enrolled after activate: %+v calls %d", again, calls)
	}
	state, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, dev := range state.Devices {
		if dev.Generation != next[0].Generation {
			t.Fatalf("inactive generation survived restart: %+v", dev)
		}
	}
	exits := []string{first[1].Name}
	if !GenerationIdle(exits, [][]string{{first[0].Name}}) {
		t.Fatal("front transport blocked retirement")
	}
	if GenerationIdle(exits, [][]string{{"warp-pool", first[1].Name}}) {
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
	if !cfg.General.Tun.Enable || !cfg.General.Tun.AutoRoute || !cfg.General.Tun.AutoDetectInterface || !cfg.General.Tun.AutoRedirect {
		t.Fatalf("tun %+v", cfg.General.Tun)
	}
	if len(cfg.General.Tun.RouteAddressSet) != 0 {
		t.Fatalf("public capture set %v", cfg.General.Tun.RouteAddressSet)
	}
	if len(cfg.General.Tun.RouteExcludeAddressSet) != 1 || cfg.General.Tun.RouteExcludeAddressSet[0] != localSet {
		t.Fatalf("exclude set %v", cfg.General.Tun.RouteExcludeAddressSet)
	}
	if !hasPrefix(cfg.General.Tun.RouteExcludeAddress, "172.16.0.0/12") || !hasPrefix(cfg.General.Tun.RouteExcludeAddress, "fc00::/7") {
		t.Fatalf("exclude prefixes %v", cfg.General.Tun.RouteExcludeAddress)
	}
	if _, ok := cfg.RuleProviders[localSet]; !ok {
		t.Fatal("missing local address set")
	}
	if len(cfg.Rules) != len(localCIDRs)+1 || cfg.Rules[len(cfg.Rules)-1].RuleType().String() != "Match" {
		t.Fatalf("rules %d last %s", len(cfg.Rules), cfg.Rules[len(cfg.Rules)-1].RuleType())
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
func hasPrefix(prefixes []netip.Prefix, cidr string) bool {
	for _, prefix := range prefixes {
		if prefix.String() == cidr {
			return true
		}
	}
	return false
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
