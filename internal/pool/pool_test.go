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
	got, err := Ensure(dir, 2, 3, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 5 {
		t.Fatalf("enroll calls %d, want 5", calls)
	}
	if got[0].Role != RoleFront || got[0].Name != "warp-front-1" || got[1].Role != RoleFront || got[1].Name != "warp-front-2" {
		t.Fatalf("fronts %+v", got[:2])
	}
	if got[2].Name != "warp-exit-1" || got[3].Name != "warp-exit-2" || got[4].Name != "warp-exit-3" {
		t.Fatalf("exits %+v", got[2:])
	}
	seenCreds := map[string]bool{}
	seenServers := map[string]bool{}
	seenPorts := map[int]bool{}
	for _, d := range got {
		if seenCreds[d.PrivateKey] || seenCreds[d.PublicKey] || seenCreds[d.IPv6] {
			t.Fatalf("duplicate credential in %+v", d)
		}
		seenCreds[d.PrivateKey] = true
		seenCreds[d.PublicKey] = true
		seenCreds[d.IPv6] = true
		if seenServers[d.Server] {
			t.Fatalf("duplicate server %s", d.Server)
		}
		seenServers[d.Server] = true
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
	again, err := Ensure(dir, 2, 3, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 5 {
		t.Fatalf("second ensure enrolled again, calls %d", calls)
	}
	if again[0].Server != got[0].Server || again[2].PrivateKey != got[2].PrivateKey {
		t.Fatal("stored identities changed")
	}

	unlock, err = Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	grown, err := Ensure(dir, 3, 4, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 7 || len(grown) != 7 {
		t.Fatalf("grow calls %d len %d devices %+v", calls, len(grown), grown)
	}
	if grown[2].Name != "warp-front-3" || grown[6].Name != "warp-exit-4" {
		t.Fatalf("grown names %+v", grown)
	}
	grownServers := map[string]bool{}
	grownPorts := map[int]bool{}
	for _, d := range grown {
		if grownServers[d.Server] {
			t.Fatalf("duplicate server after grow %s", d.Server)
		}
		grownServers[d.Server] = true
		if grownPorts[d.Port] {
			t.Fatalf("duplicate port %d after grow in %+v", d.Port, grown)
		}
		grownPorts[d.Port] = true
	}
}

func TestEnsureLegacyFrontCompatibilityAndNumericSort(t *testing.T) {
	dir := t.TempDir()
	legacy := fileState{
		Devices: []Device{
			{
				Role:       RoleFront,
				Name:       FrontName,
				PrivateKey: "priv-legacy",
				PublicKey:  "pub-legacy",
				IP:         "172.16.0.2",
				IPv6:       "2606:4700:110::legacy",
				Server:     "162.159.198.2",
				Port:       443,
			},
		},
	}
	if err := save(dir, legacy); err != nil {
		t.Fatal(err)
	}
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
	devs, err := Ensure(dir, 2, 10, reg)
	if err != nil {
		t.Fatal(err)
	}
	if devs[0].Name != FrontName || devs[1].Name != "warp-front-2" {
		t.Fatalf("fronts %+v", devs[:2])
	}
	if devs[2].Name != "warp-exit-1" || devs[11].Name != "warp-exit-10" {
		t.Fatalf("exit numeric order broken: %+v", devs[2:])
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

	// 2 fronts + 5 exits = 7 devices: every node gets a unique supported port.
	devs, err := Ensure(dir, 2, 5, reg)
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
	more, err := Ensure(dir, 3, 7, reg)
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
			IPv6:       "2606:4700:110::" + name,
		}, nil
	}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	first, err := Ensure(dir, 2, 2, reg)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Rotate(dir, 2, 2, reg)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 8 {
		t.Fatalf("calls %d, want 8", calls)
	}
	if next[0].Name != "warp-front-g1-1" || next[1].Name != "warp-front-g1-2" || next[2].Name != "warp-exit-g1-1" || next[3].Name != "warp-exit-g1-2" {
		t.Fatalf("next %+v", next)
	}
	usedServers := map[string]bool{}
	usedCreds := map[string]bool{}
	for _, d := range first {
		usedServers[d.Server] = true
		usedCreds[d.PrivateKey] = true
	}
	for _, d := range next {
		if usedServers[d.Server] {
			t.Fatalf("server %s was reused across generations", d.Server)
		}
		usedServers[d.Server] = true
		if usedCreds[d.PrivateKey] {
			t.Fatalf("credential %s was reused across generations", d.PrivateKey)
		}
		usedCreds[d.PrivateKey] = true
	}
	portCounts := map[int]int{}
	for _, d := range append(slices.Clone(first), next...) {
		if !slices.Contains(masquePorts, d.Port) {
			t.Fatalf("device %s got unsupported port %d", d.Name, d.Port)
		}
		portCounts[d.Port]++
	}
	for _, p := range masquePorts {
		if portCounts[p] < 1 || portCounts[p] > 2 {
			t.Fatalf("unbalanced port %d count %d across generations", p, portCounts[p])
		}
	}
	pending, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if activeGeneration(pending) != first[0].Generation {
		t.Fatalf("unprobed generation %d became active", activeGeneration(pending))
	}
	recovered, err := Ensure(dir, 2, 2, reg)
	if err != nil {
		t.Fatal(err)
	}
	if recovered[0].Name != first[0].Name || calls != 8 {
		t.Fatalf("restart kept the unprobed generation: %+v calls %d", recovered, calls)
	}
	next, err = Rotate(dir, 2, 2, reg)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 12 {
		t.Fatalf("calls %d, want 12", calls)
	}
	if err := Activate(dir, next[0].Generation); err != nil {
		t.Fatal(err)
	}
	again, err := Ensure(dir, 2, 2, reg)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Name != next[0].Name || calls != 12 {
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
	exits := []string{first[2].Name, first[3].Name}
	if !GenerationIdle(exits, [][]string{{FrontGroupName(0), first[0].Name}}) {
		t.Fatal("front transport blocked retirement")
	}
	if GenerationIdle(exits, [][]string{{PoolName, first[2].Name}}) {
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
	devices := []Device{
		mustDevice(t, RoleFront, "warp-front-1"),
		mustDevice(t, RoleFront, "warp-front-2"),
		mustDevice(t, RoleExit, "warp-exit-1"),
		mustDevice(t, RoleExit, "warp-exit-2"),
		mustDevice(t, RoleExit, "warp-exit-3"),
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
	for _, name := range []string{"warp-front-1", "warp-front-2"} {
		front := cfg.Proxies[name].ProxyInfo()
		if front.DialerProxy != "" {
			t.Fatalf("%s dialer %q", name, front.DialerProxy)
		}
	}
	frontGroupName := FrontGroupName(0)
	for _, name := range []string{"warp-exit-1", "warp-exit-2", "warp-exit-3"} {
		info := cfg.Proxies[name].ProxyInfo()
		if info.DialerProxy != frontGroupName {
			t.Fatalf("%s dialer %q, want %q", name, info.DialerProxy, frontGroupName)
		}
	}
	frontGroup, ok := cfg.Proxies[frontGroupName]
	if !ok {
		t.Fatal("missing front pool group")
	}
	frontEncoded, err := frontGroup.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	frontText := string(frontEncoded)
	if !strings.Contains(frontText, "warp-front-1") || !strings.Contains(frontText, "warp-front-2") || strings.Contains(frontText, "warp-exit-1") {
		t.Fatalf("front group %s", frontText)
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
	if !strings.Contains(text, "warp-exit-1") || !strings.Contains(text, "warp-exit-2") || !strings.Contains(text, "warp-exit-3") || strings.Contains(text, "warp-front") {
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
