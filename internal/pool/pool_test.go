package pool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
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
	spec := Spec{FrontsH3: 2, ExitsH3: 3, FrontsH2: 1, ExitsH2: 1}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Ensure(dir, spec, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 7 {
		t.Fatalf("enroll calls %d, want 7", calls)
	}
	wantNames := []string{
		"warp-front-h3-1", "warp-front-h3-2",
		"warp-front-h2-1",
		"warp-exit-h3-1", "warp-exit-h3-2", "warp-exit-h3-3",
		"warp-exit-h2-1",
	}
	for i, want := range wantNames {
		if got[i].Name != want {
			t.Fatalf("device[%d] = %s, want %s", i, got[i].Name, want)
		}
	}
	seenCreds := map[string]bool{}
	seenPairs := map[string]bool{}
	seenH2Servers := map[string]bool{}
	for _, d := range got {
		if seenCreds[d.PrivateKey] || seenCreds[d.PublicKey] || seenCreds[d.IPv6] {
			t.Fatalf("duplicate credential in %+v", d)
		}
		seenCreds[d.PrivateKey] = true
		seenCreds[d.PublicKey] = true
		seenCreds[d.IPv6] = true
		pair := fmt.Sprintf("%s:%d", d.Server, d.Port)
		if seenPairs[pair] {
			t.Fatalf("duplicate endpoint %s", pair)
		}
		seenPairs[pair] = true
		if !slices.Contains(masquePorts, d.Port) {
			t.Fatalf("unsupported port %d", d.Port)
		}
		if d.Network == NetworkH3 {
			if d.Server != "162.159.198.1" && d.Server != "162.159.198.2" {
				t.Fatalf("h3 device %s got unexpected server %s", d.Name, d.Server)
			}
		} else {
			if d.Server == "162.159.198.1" || d.Server == "162.159.198.2" {
				t.Fatalf("h2 device %s reserved h3 server %s", d.Name, d.Server)
			}
			if seenH2Servers[d.Server] {
				t.Fatalf("duplicate h2 server %s", d.Server)
			}
			seenH2Servers[d.Server] = true
		}
	}

	unlock, err = Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Ensure(dir, spec, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 7 {
		t.Fatalf("second ensure enrolled again, calls %d", calls)
	}
	if again[0].Server != got[0].Server || again[3].PrivateKey != got[3].PrivateKey {
		t.Fatal("stored identities changed")
	}

	unlock, err = Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	grownSpec := Spec{FrontsH3: 2, ExitsH3: 3, FrontsH2: 2, ExitsH2: 2}
	grown, err := Ensure(dir, grownSpec, reg)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 9 || len(grown) != 9 {
		t.Fatalf("grow calls %d len %d devices %+v", calls, len(grown), grown)
	}
	if grown[3].Name != "warp-front-h2-2" || grown[8].Name != "warp-exit-h2-2" {
		t.Fatalf("grown names %+v", grown)
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
	devs, err := Ensure(dir, Spec{FrontsH3: 1, ExitsH3: 1, FrontsH2: 2, ExitsH2: 10}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if devs[1].Name != FrontName || devs[2].Name != "warp-front-h2-2" {
		t.Fatalf("h2 fronts %+v", devs[1:3])
	}
	if devs[4].Name != "warp-exit-h2-1" || devs[13].Name != "warp-exit-h2-10" {
		t.Fatalf("exit numeric order broken: %+v", devs[4:])
	}
	for _, d := range devs {
		if d.Network == NetworkH3 && d.Server == "162.159.198.2" && d.Port == 443 {
			t.Fatalf("h3 device collided with legacy endpoint 162.159.198.2:443: %+v", d)
		}
	}
}

func TestSpecValidation(t *testing.T) {
	bad := []Spec{
		{FrontsH3: 0, ExitsH3: 0, FrontsH2: 0, ExitsH2: 0},
		{FrontsH3: 1, ExitsH3: 0, FrontsH2: 1, ExitsH2: 1},
		{FrontsH3: 0, ExitsH3: 1, FrontsH2: 1, ExitsH2: 1},
		{FrontsH3: 2, ExitsH3: 6, FrontsH2: 1, ExitsH2: 1}, // 8 H3 devices > maxH3PerGen (7)
		{FrontsH3: 1, ExitsH3: 1, FrontsH2: 1, ExitsH2: 0},
	}
	for _, spec := range bad {
		if err := spec.validate(); err == nil {
			t.Fatalf("expected error for %+v", spec)
		}
	}
	good := []Spec{
		{FrontsH3: 2, ExitsH3: 3, FrontsH2: 1, ExitsH2: 1},
		{FrontsH3: 2, ExitsH3: 5, FrontsH2: 0, ExitsH2: 0},
		{FrontsH3: 0, ExitsH3: 0, FrontsH2: 2, ExitsH2: 4},
	}
	for _, spec := range good {
		if err := spec.validate(); err != nil {
			t.Fatalf("unexpected error for %+v: %v", spec, err)
		}
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

	// 2 H3 fronts + 5 H3 exits = 7 devices: every H3 node gets a unique port.
	devs, err := Ensure(dir, Spec{FrontsH3: 2, ExitsH3: 5}, reg)
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

	// Adding H2 track past len(masquePorts) stays balanced across all ports.
	more, err := Ensure(dir, Spec{FrontsH3: 2, ExitsH3: 5, FrontsH2: 2, ExitsH2: 5}, reg)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[int]int{}
	for _, d := range more {
		counts[d.Port]++
	}
	for _, p := range masquePorts {
		if counts[p] != 2 {
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
	spec := Spec{FrontsH3: 2, ExitsH3: 3, FrontsH2: 1, ExitsH2: 1}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	first, err := Ensure(dir, spec, reg)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Rotate(dir, spec, reg)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 14 {
		t.Fatalf("calls %d, want 14", calls)
	}
	if next[0].Name != "warp-front-h3-g1-1" || next[2].Name != "warp-front-h2-g1-1" || next[3].Name != "warp-exit-h3-g1-1" || next[6].Name != "warp-exit-h2-g1-1" {
		t.Fatalf("next %+v", next)
	}
	usedPairs := map[string]bool{}
	usedCreds := map[string]bool{}
	for _, d := range append(slices.Clone(first), next...) {
		pair := fmt.Sprintf("%s:%d", d.Server, d.Port)
		if usedPairs[pair] {
			t.Fatalf("endpoint %s was reused across generations", pair)
		}
		usedPairs[pair] = true
		if usedCreds[d.PrivateKey] {
			t.Fatalf("credential %s was reused across generations", d.PrivateKey)
		}
		usedCreds[d.PrivateKey] = true
	}

	pending, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if activeGeneration(pending) != first[0].Generation {
		t.Fatalf("unprobed generation %d became active", activeGeneration(pending))
	}
	recovered, err := Ensure(dir, spec, reg)
	if err != nil {
		t.Fatal(err)
	}
	if recovered[0].Name != first[0].Name || calls != 14 {
		t.Fatalf("restart kept the unprobed generation: %+v calls %d", recovered, calls)
	}
	next, err = Rotate(dir, spec, reg)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 21 {
		t.Fatalf("calls %d, want 21", calls)
	}
	if err := Activate(dir, next[0].Generation); err != nil {
		t.Fatal(err)
	}
	again, err := Ensure(dir, spec, reg)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Name != next[0].Name || calls != 21 {
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
	exits := []string{first[3].Name, first[4].Name, first[5].Name, first[6].Name}
	if !GenerationIdle(exits, [][]string{{FrontGroupName(NetworkH3, 0), first[0].Name}}) {
		t.Fatal("front transport blocked retirement")
	}
	if GenerationIdle(exits, [][]string{{PoolName, first[3].Name}}) {
		t.Fatal("live exit was treated as idle")
	}
}

func TestRotateConsecutiveSixH3GenerationsAndZeroEnrollOnExhaustion(t *testing.T) {
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
	spec := Spec{FrontsH3: 3, ExitsH3: 3, FrontsH2: 1, ExitsH2: 1}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	cur, err := Ensure(dir, spec, reg)
	if err != nil {
		t.Fatal(err)
	}
	for round := range 4 {
		next, err := Rotate(dir, spec, reg)
		if err != nil {
			t.Fatalf("round %d rotate: %v", round, err)
		}
		if err := Activate(dir, next[0].Generation); err != nil {
			t.Fatalf("round %d activate: %v", round, err)
		}
		if err := ForgetGeneration(dir, cur[0].Generation); err != nil {
			t.Fatalf("round %d forget: %v", round, err)
		}
		cur = next
	}

	// Keep active (gen 4) and also stage gen 5 without forgetting gen 4:
	// 6 + 6 = 12 H3 endpoints used out of 14. Attempting gen 6 must fail before
	// calling reg() once.
	if _, err := Rotate(dir, spec, reg); err != nil {
		t.Fatalf("staging extra generation failed: %v", err)
	}
	callsBefore := calls
	if _, err := Rotate(dir, spec, reg); err == nil {
		t.Fatal("expected error when 12/14 H3 endpoints are already occupied")
	}
	if calls != callsBefore {
		t.Fatalf("Rotate called reg %d times despite exhausted H3 endpoints", calls-callsBefore)
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
		mustDevice(t, RoleFront, NetworkH3, "warp-front-h3-1", "162.159.198.1", 4443),
		mustDevice(t, RoleFront, NetworkH3, "warp-front-h3-2", "162.159.198.2", 8443),
		mustDevice(t, RoleFront, NetworkH2, "warp-front-h2-1", "162.159.198.10", 4500),
		mustDevice(t, RoleExit, NetworkH3, "warp-exit-h3-1", "162.159.198.1", 500),
		mustDevice(t, RoleExit, NetworkH3, "warp-exit-h3-2", "162.159.198.2", 1701),
		mustDevice(t, RoleExit, NetworkH3, "warp-exit-h3-3", "162.159.198.1", 8095),
		mustDevice(t, RoleExit, NetworkH2, "warp-exit-h2-1", "162.159.198.20", 443),
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
	for _, name := range []string{"warp-front-h3-1", "warp-front-h3-2", "warp-front-h2-1"} {
		front := cfg.Proxies[name].ProxyInfo()
		if front.DialerProxy != "" {
			t.Fatalf("%s dialer %q", name, front.DialerProxy)
		}
	}
	frontH3GroupName := FrontGroupName(NetworkH3, 0)
	frontH2GroupName := FrontGroupName(NetworkH2, 0)
	for _, name := range []string{"warp-exit-h3-1", "warp-exit-h3-2", "warp-exit-h3-3"} {
		info := cfg.Proxies[name].ProxyInfo()
		if info.DialerProxy != frontH3GroupName {
			t.Fatalf("%s dialer %q, want %q", name, info.DialerProxy, frontH3GroupName)
		}
	}
	if info := cfg.Proxies["warp-exit-h2-1"].ProxyInfo(); info.DialerProxy != frontH2GroupName {
		t.Fatalf("warp-exit-h2-1 dialer %q, want %q", info.DialerProxy, frontH2GroupName)
	}
	frontH3Encoded, err := cfg.Proxies[frontH3GroupName].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(frontH3Encoded), "warp-front-h3-1") || strings.Contains(string(frontH3Encoded), "warp-front-h2-1") {
		t.Fatalf("h3 front group %s", string(frontH3Encoded))
	}
	frontH2Encoded, err := cfg.Proxies[frontH2GroupName].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(frontH2Encoded), "warp-front-h2-1") || strings.Contains(string(frontH2Encoded), "warp-front-h3-1") {
		t.Fatalf("h2 front group %s", string(frontH2Encoded))
	}
	encoded, err := cfg.Proxies[PoolName].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, want := range []string{"warp-exit-h3-1", "warp-exit-h3-2", "warp-exit-h3-3", "warp-exit-h2-1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("warp-pool missing %s: %s", want, text)
		}
	}
	if strings.Contains(text, "warp-front") {
		t.Fatalf("warp-pool leaked front: %s", text)
	}
	yamlText := string(raw)
	if !strings.Contains(yamlText, "congestion-controller: bbr") || !strings.Contains(yamlText, "network: h2") {
		t.Fatalf("missing expected protocol directives:\n%s", yamlText)
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

func mustDevice(t *testing.T, role, network, name, server string, port int) Device {
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
		Network:    network,
		Name:       name,
		PrivateKey: base64.StdEncoding.EncodeToString(sec1),
		PublicKey:  base64.StdEncoding.EncodeToString(spki),
		IP:         "172.16.0.2",
		IPv6:       "2606:4700:110::1",
		Server:     server,
		Port:       port,
	}
}
