package pool

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/metacubex/mihomo/component/trie"
	"go.yaml.in/yaml/v3"
)

const DefaultDirectFile = "direct.yaml"

// DirectRules holds user-configured bypass targets routed via DIRECT instead of warp-pool.
type DirectRules struct {
	Domains []string
	CIDRs   []netip.Prefix
	Rules   []string
}

type directFile struct {
	Domains []string `yaml:"domains"`
	CIDRs   []string `yaml:"cidrs"`
	Rules   []string `yaml:"rules"`
}

type directBuilder struct {
	out        DirectRules
	seenDomain map[string]bool
	seenCIDR   map[netip.Prefix]bool
	seenRule   map[string]bool
}

func newDirectBuilder() *directBuilder {
	return &directBuilder{
		seenDomain: map[string]bool{},
		seenCIDR:   map[netip.Prefix]bool{},
		seenRule:   map[string]bool{},
	}
}

func (b *directBuilder) addDomain(raw string) error {
	norm, err := normalizeDirectDomain(raw)
	if err != nil {
		return err
	}
	if b.seenDomain[norm] {
		return nil
	}
	b.seenDomain[norm] = true
	b.out.Domains = append(b.out.Domains, norm)
	return nil
}

func (b *directBuilder) addCIDR(raw string) error {
	prefix, err := parseDirectCIDR(raw)
	if err != nil {
		return err
	}
	if b.seenCIDR[prefix] {
		return nil
	}
	b.seenCIDR[prefix] = true
	b.out.CIDRs = append(b.out.CIDRs, prefix)
	return nil
}

func (b *directBuilder) addRule(raw string) error {
	rule, err := normalizeDirectRule(raw)
	if err != nil {
		return err
	}
	if b.seenRule[rule] {
		return nil
	}
	b.seenRule[rule] = true
	b.out.Rules = append(b.out.Rules, rule)
	return nil
}

// LoadDirect loads bypass rules from the comma-separated envList (WARP_DIRECT)
// and a YAML config file. When filePath is empty, filepath.Join(dataDir, DefaultDirectFile)
// is loaded if it exists; an explicit filePath must exist.
func LoadDirect(dataDir, envList, filePath string) (DirectRules, error) {
	b := newDirectBuilder()
	if err := loadDirectFile(b, dataDir, filePath); err != nil {
		return DirectRules{}, err
	}
	for _, item := range strings.Split(envList, ",") {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		if prefix, err := parseDirectCIDR(s); err == nil {
			if !b.seenCIDR[prefix] {
				b.seenCIDR[prefix] = true
				b.out.CIDRs = append(b.out.CIDRs, prefix)
			}
			continue
		}
		if err := b.addDomain(s); err != nil {
			return DirectRules{}, fmt.Errorf("WARP_DIRECT %q: %w", s, err)
		}
	}
	return b.out, nil
}

func loadDirectFile(b *directBuilder, dataDir, filePath string) error {
	explicit := strings.TrimSpace(filePath) != ""
	path := strings.TrimSpace(filePath)
	if !explicit {
		path = filepath.Join(dataDir, DefaultDirectFile)
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read direct config %s: %w", path, err)
	}
	var cfg directFile
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse direct config %s: %w", path, err)
	}
	for _, d := range cfg.Domains {
		if err := b.addDomain(d); err != nil {
			return fmt.Errorf("direct config %s domains: %w", path, err)
		}
	}
	for _, c := range cfg.CIDRs {
		if err := b.addCIDR(c); err != nil {
			return fmt.Errorf("direct config %s cidrs: %w", path, err)
		}
	}
	for _, r := range cfg.Rules {
		if err := b.addRule(r); err != nil {
			return fmt.Errorf("direct config %s rules: %w", path, err)
		}
	}
	return nil
}

func normalizeDirectDomain(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", errors.New("empty domain")
	}
	if strings.ContainsAny(s, " \t\r\n/,") || strings.Contains(s, "://") {
		return "", fmt.Errorf("invalid domain %q", raw)
	}
	suffix := false
	switch {
	case strings.HasPrefix(s, "*."):
		suffix = true
		s = s[2:]
	case strings.HasPrefix(s, "+."):
		suffix = true
		s = s[2:]
	case strings.HasPrefix(s, "."):
		suffix = true
		s = s[1:]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || strings.Contains(s, "*") {
		return "", fmt.Errorf("invalid domain %q", raw)
	}
	if suffix {
		s = "+." + s
	}
	if _, err := trie.ValidAndSplitDomain(s); err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", raw, err)
	}
	return s, nil
}

func parseDirectCIDR(raw string) (netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, errors.New("empty cidr")
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid cidr or ip %q", raw)
}

func normalizeDirectRule(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty rule")
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid rule %q: want TYPE,PAYLOAD[,DIRECT][,no-resolve]", raw)
	}
	kind := strings.ToUpper(parts[0])
	if kind == "MATCH" {
		return "", fmt.Errorf("rule %q: MATCH is not allowed in direct rules", raw)
	}
	parts[0] = kind

	var tail []string
	switch len(parts) {
	case 2:
		tail = []string{"DIRECT"}
	case 3:
		switch strings.ToUpper(parts[2]) {
		case "", "DIRECT":
			tail = []string{"DIRECT"}
		case "NO-RESOLVE":
			tail = []string{"DIRECT", "no-resolve"}
		default:
			return "", fmt.Errorf("rule %q must target DIRECT, got %q", raw, parts[2])
		}
	case 4:
		if strings.ToUpper(parts[2]) != "DIRECT" {
			return "", fmt.Errorf("rule %q must target DIRECT, got %q", raw, parts[2])
		}
		if strings.ToLower(parts[3]) != "no-resolve" {
			return "", fmt.Errorf("rule %q has unsupported option %q", raw, parts[3])
		}
		tail = []string{"DIRECT", "no-resolve"}
	default:
		return "", fmt.Errorf("invalid rule %q: too many fields", raw)
	}
	return strings.Join(append(parts[:2], tail...), ","), nil
}
