package pool

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
)

func TestLoadDirectEmptyAndMissing(t *testing.T) {
	dir := t.TempDir()

	got, err := LoadDirect(dir, "", "")
	if err != nil {
		t.Fatalf("empty default load: %v", err)
	}
	if len(got.Domains) != 0 || len(got.CIDRs) != 0 || len(got.Rules) != 0 {
		t.Fatalf("expected empty rules, got %+v", got)
	}

	if _, err := LoadDirect(dir, "", filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected error for missing explicit direct file")
	}

	if err := os.WriteFile(filepath.Join(dir, DefaultDirectFile), []byte("# comment only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = LoadDirect(dir, "", "")
	if err != nil {
		t.Fatalf("comment-only file: %v", err)
	}
	if len(got.Domains) != 0 || len(got.CIDRs) != 0 || len(got.Rules) != 0 {
		t.Fatalf("expected empty rules for comment-only file, got %+v", got)
	}
}

func TestLoadDirectMergesFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
domains:
  - www.googleapis.com
  - .googleusercontent.com
  - "*.gstatic.com"
  - +.example.org
  - WWW.GOOGLEAPIS.COM
cidrs:
  - 203.0.113.0/24
  - 198.51.100.7
rules:
  - DOMAIN-KEYWORD,rclone
  - domain-suffix,foo.example,direct
  - IP-CIDR,192.0.2.0/24,no-resolve
  - IP-CIDR6,2001:db8::/32,DIRECT,no-resolve
`
	if err := os.WriteFile(filepath.Join(dir, DefaultDirectFile), []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	env := "drive.googleapis.com, .googleusercontent.com, 2001:db8:1::/48, 203.0.113.0/24"
	got, err := LoadDirect(dir, env, "")
	if err != nil {
		t.Fatalf("load direct: %v", err)
	}

	wantDomains := []string{
		"www.googleapis.com",
		"+.googleusercontent.com",
		"+.gstatic.com",
		"+.example.org",
		"drive.googleapis.com",
	}
	if !slices.Equal(got.Domains, wantDomains) {
		t.Fatalf("domains = %v, want %v", got.Domains, wantDomains)
	}

	var gotCIDRs []string
	for _, p := range got.CIDRs {
		gotCIDRs = append(gotCIDRs, p.String())
	}
	wantCIDRs := []string{"203.0.113.0/24", "198.51.100.7/32", "2001:db8:1::/48"}
	if !slices.Equal(gotCIDRs, wantCIDRs) {
		t.Fatalf("cidrs = %v, want %v", gotCIDRs, wantCIDRs)
	}

	wantRules := []string{
		"DOMAIN-KEYWORD,rclone,DIRECT",
		"DOMAIN-SUFFIX,foo.example,DIRECT",
		"IP-CIDR,192.0.2.0/24,DIRECT,no-resolve",
		"IP-CIDR6,2001:db8::/32,DIRECT,no-resolve",
	}
	if !slices.Equal(got.Rules, wantRules) {
		t.Fatalf("rules = %v, want %v", got.Rules, wantRules)
	}
}

func TestLoadDirectValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		env  string
	}{
		{
			name: "unknown yaml field",
			yaml: "domain:\n  - example.com\n",
		},
		{
			name: "url instead of domain in file",
			yaml: "domains:\n  - https://drive.google.com\n",
		},
		{
			name: "invalid domain in env",
			env:  "bad/domain",
		},
		{
			name: "invalid cidr",
			yaml: "cidrs:\n  - not-a-cidr\n",
		},
		{
			name: "non-direct target",
			yaml: "rules:\n  - DOMAIN,example.com,PROXY\n",
		},
		{
			name: "match rule forbidden",
			yaml: "rules:\n  - MATCH,DIRECT\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.yaml != "" {
				if err := os.WriteFile(filepath.Join(dir, DefaultDirectFile), []byte(tc.yaml), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadDirect(dir, tc.env, ""); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestYAMLWithDirectParsesAsMihomo(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
domains:
  - www.googleapis.com
  - .googleusercontent.com
cidrs:
  - 203.0.113.0/24
rules:
  - DOMAIN-KEYWORD,rclone
`
	customPath := filepath.Join(dir, "custom-direct.yaml")
	if err := os.WriteFile(customPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
	direct, err := LoadDirect(dir, "accounts.google.com", customPath)
	if err != nil {
		t.Fatalf("load direct: %v", err)
	}

	devices := []Device{
		mustDevice(t, RoleFront, NetworkH3, "warp-front-h3-1", "162.159.198.1", 4443),
		mustDevice(t, RoleExit, NetworkH3, "warp-exit-h3-1", "162.159.198.2", 8443),
		mustDevice(t, RoleFront, NetworkH2, "warp-front-h2-1", "162.159.198.10", 4500),
		mustDevice(t, RoleExit, NetworkH2, "warp-exit-h2-1", "162.159.198.20", 443),
	}
	for _, tun := range []bool{true, false} {
		raw, err := YAMLWithDirect(devices, tun, direct)
		if err != nil {
			t.Fatalf("tun=%t yaml: %v", tun, err)
		}
		C.SetHomeDir(t.TempDir())
		cfg, err := config.Parse(raw)
		if err != nil {
			t.Fatalf("tun=%t parse: %v\n%s", tun, err, raw)
		}
		rp, ok := cfg.RuleProviders[directDomainSet]
		if !ok {
			t.Fatalf("tun=%t missing %s provider", tun, directDomainSet)
		}
		if rp.Behavior().String() != "Domain" {
			t.Fatalf("tun=%t provider behavior %s", tun, rp.Behavior())
		}
		for _, host := range []string{"www.googleapis.com", "googleusercontent.com", "lh3.googleusercontent.com", "accounts.google.com"} {
			if !rp.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}) {
				t.Fatalf("tun=%t expected %s to match %s", tun, host, directDomainSet)
			}
		}
		if rp.Match(&C.Metadata{Host: "example.com"}, C.RuleMatchHelper{}) {
			t.Fatalf("tun=%t unexpected match for example.com", tun)
		}
		if len(cfg.DNS.NameServerPolicy) != 1 || len(cfg.DNS.NameServerPolicy[0].NameServers) != 1 || cfg.DNS.NameServerPolicy[0].NameServers[0].ProxyName != "DIRECT" {
			t.Fatalf("tun=%t nameserver policy %+v", tun, cfg.DNS.NameServerPolicy)
		}
		// Expected rule order: localCIDRs + RULE-SET(directDomainSet) + 1 CIDR + 1 custom rule + MATCH.
		wantCount := len(localCIDRs) + 1 + 1 + 1 + 1
		if len(cfg.Rules) != wantCount {
			t.Fatalf("tun=%t rules count %d, want %d\n%s", tun, len(cfg.Rules), wantCount, raw)
		}
		ruleSetRule := cfg.Rules[len(localCIDRs)]
		if ruleSetRule.RuleType().String() != "RuleSet" || ruleSetRule.Adapter() != "DIRECT" {
			t.Fatalf("tun=%t unexpected rule at %d: %s -> %s", tun, len(localCIDRs), ruleSetRule.RuleType(), ruleSetRule.Adapter())
		}
		last := cfg.Rules[len(cfg.Rules)-1]
		if last.RuleType().String() != "Match" || last.Adapter() != PoolName {
			t.Fatalf("tun=%t last rule %s -> %s", tun, last.RuleType(), last.Adapter())
		}
		if !strings.Contains(string(raw), "\"rule-set:"+directDomainSet+"\":") {
			t.Fatalf("tun=%t missing nameserver-policy key in YAML:\n%s", tun, raw)
		}
	}
}
