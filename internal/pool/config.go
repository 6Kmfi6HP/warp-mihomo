package pool

import (
	"fmt"
	"strconv"
	"strings"
)

// YAML renders a mihomo config without custom bypass rules.
func YAML(devices []Device, tun bool) ([]byte, error) {
	return YAMLWithDirect(devices, tun, DirectRules{})
}

// YAMLWithDirect renders a mihomo config. Front devices dial MASQUE directly and
// sit in a generation-scoped front load-balance group. Each exit sets
// dialer-proxy to that front group, and warp-pool load-balances across exits.
// With TUN, auto-redirect mark mode captures public egress, including sockets
// bound to a namespace address. Local destinations are excluded before DNS
// hijack and stay on the container network. Custom direct targets bypass
// warp-pool via DIRECT (and direct DoH resolution for domain entries). Mihomo
// marks its own dials so the fronts and DIRECT dials still leave through the
// container NIC.
func YAMLWithDirect(devices []Device, tun bool, direct DirectRules) ([]byte, error) {
	fronts, exits, gen, err := SplitRoles(devices)
	if err != nil {
		return nil, err
	}
	frontGroup := FrontGroupName(gen)
	var b strings.Builder
	b.WriteString("allow-lan: false\n")
	b.WriteString("mode: rule\n")
	b.WriteString("log-level: info\n")
	b.WriteString("ipv6: true\n")
	b.WriteString("find-process-mode: off\n")
	b.WriteString("geo-auto-update: false\n")
	b.WriteString("\n")
	b.WriteString("tun:\n")
	fmt.Fprintf(&b, "  enable: %t\n", tun)
	b.WriteString("  stack: mips\n")
	b.WriteString("  auto-route: true\n")
	b.WriteString("  auto-detect-interface: true\n")
	if tun {
		b.WriteString("  auto-redirect: true\n")
		b.WriteString("  route-exclude-address:\n")
		for _, cidr := range localCIDRs {
			b.WriteString("    - " + strconv.Quote(cidr) + "\n")
		}
		b.WriteString("  route-exclude-address-set:\n")
		b.WriteString("    - " + localSet + "\n")
	}
	b.WriteString("  dns-hijack:\n")
	b.WriteString("    - any:53\n")
	b.WriteString("    - tcp://any:53\n")
	b.WriteString("\n")
	b.WriteString("dns:\n")
	b.WriteString("  enable: true\n")
	b.WriteString("  ipv6: true\n")
	b.WriteString("  enhanced-mode: redir-host\n")
	b.WriteString("  respect-rules: true\n")
	b.WriteString("  default-nameserver:\n")
	b.WriteString("    - 1.1.1.1\n")
	b.WriteString("  nameserver:\n")
	b.WriteString("    - \"https://1.1.1.1/dns-query#" + PoolName + "\"\n")
	if len(direct.Domains) > 0 {
		b.WriteString("  nameserver-policy:\n")
		fmt.Fprintf(&b, "    \"rule-set:%s\":\n", directDomainSet)
		b.WriteString("      - \"https://1.1.1.1/dns-query#DIRECT\"\n")
	}
	b.WriteString("  proxy-server-nameserver:\n")
	b.WriteString("    - 1.1.1.1\n")
	b.WriteString("\n")
	b.WriteString("proxies:\n")
	for _, d := range fronts {
		if err := writeProxy(&b, d, ""); err != nil {
			return nil, err
		}
	}
	for _, d := range exits {
		if err := writeProxy(&b, d, frontGroup); err != nil {
			return nil, err
		}
	}
	b.WriteString("\n")
	b.WriteString("proxy-groups:\n")
	writeLoadBalanceGroup(&b, frontGroup, false, fronts)
	writeLoadBalanceGroup(&b, PoolName, true, exits)
	b.WriteString("\n")
	if tun || len(direct.Domains) > 0 {
		b.WriteString("rule-providers:\n")
		if tun {
			b.WriteString("  " + localSet + ":\n")
			b.WriteString("    type: inline\n")
			b.WriteString("    behavior: ipcidr\n")
			b.WriteString("    payload:\n")
			for _, cidr := range localCIDRs {
				b.WriteString("      - " + strconv.Quote(cidr) + "\n")
			}
		}
		if len(direct.Domains) > 0 {
			b.WriteString("  " + directDomainSet + ":\n")
			b.WriteString("    type: inline\n")
			b.WriteString("    behavior: domain\n")
			b.WriteString("    payload:\n")
			for _, domain := range direct.Domains {
				b.WriteString("      - " + strconv.Quote(domain) + "\n")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("rules:\n")
	for _, cidr := range localCIDRs {
		kind := "IP-CIDR"
		if strings.Contains(cidr, ":") {
			kind = "IP-CIDR6"
		}
		fmt.Fprintf(&b, "  - %s,%s,DIRECT,no-resolve\n", kind, cidr)
	}
	if len(direct.Domains) > 0 {
		fmt.Fprintf(&b, "  - RULE-SET,%s,DIRECT\n", directDomainSet)
	}
	for _, prefix := range direct.CIDRs {
		kind := "IP-CIDR"
		if prefix.Addr().Is6() {
			kind = "IP-CIDR6"
		}
		fmt.Fprintf(&b, "  - %s,%s,DIRECT,no-resolve\n", kind, prefix.String())
	}
	for _, rule := range direct.Rules {
		b.WriteString("  - " + rule + "\n")
	}
	b.WriteString("  - MATCH," + PoolName + "\n")
	return []byte(b.String()), nil
}

func writeLoadBalanceGroup(b *strings.Builder, name string, lazy bool, members []Device) {
	b.WriteString("  - name: " + name + "\n")
	b.WriteString("    type: load-balance\n")
	b.WriteString("    strategy: round-robin\n")
	fmt.Fprintf(b, "    lazy: %t\n", lazy)
	b.WriteString("    url: https://www.gstatic.com/generate_204\n")
	b.WriteString("    expected-status: \"204\"\n")
	b.WriteString("    interval: 60\n")
	b.WriteString("    timeout: 5000\n")
	b.WriteString("    proxies:\n")
	for _, d := range members {
		b.WriteString("      - " + d.Name + "\n")
	}
}

func writeProxy(b *strings.Builder, d Device, dialer string) error {
	if d.Name == "" || d.PrivateKey == "" || d.PublicKey == "" || d.Server == "" || d.IP == "" || d.IPv6 == "" || d.Port == 0 {
		return fmt.Errorf("device %q is incomplete", d.Name)
	}
	if dialer != "" && d.Role != RoleExit {
		return fmt.Errorf("device %s cannot dial through the front", d.Name)
	}
	fmt.Fprintf(b, "  - name: %s\n", d.Name)
	b.WriteString("    type: masque\n")
	fmt.Fprintf(b, "    server: %s\n", strconv.Quote(d.Server))
	fmt.Fprintf(b, "    port: %d\n", d.Port)
	fmt.Fprintf(b, "    private-key: %s\n", strconv.Quote(d.PrivateKey))
	fmt.Fprintf(b, "    public-key: %s\n", strconv.Quote(d.PublicKey))
	fmt.Fprintf(b, "    ip: %s\n", strconv.Quote(d.IP))
	fmt.Fprintf(b, "    ipv6: %s\n", strconv.Quote(d.IPv6))
	b.WriteString("    mtu: 1280\n")
	b.WriteString("    udp: true\n")
	b.WriteString("    network: h2\n")
	b.WriteString("    sni: consumer-masque.cloudflareclient.com\n")
	b.WriteString("    remote-dns-resolve: true\n")
	if dialer != "" {
		b.WriteString("    dialer-proxy: " + dialer + "\n")
	}
	b.WriteString("    dns:\n")
	b.WriteString("      - 1.1.1.1\n")
	b.WriteString("      - 1.0.0.1\n")
	return nil
}

const (
	localSet        = "warp-local"
	directDomainSet = "warp-direct-domain"
)

// localCIDRs are destinations that stay on the container network. The same
// list is installed before sing-tun's DNS hijack and as the rule-provider that
// enables auto-redirect mark mode. Prefixes must not touch: sing-tun encodes
// each range as [start, end), so an end that equals the next start is rejected.
// A range ending at the last address is also rejected. 198.18.0.0/15 is this
// stack's TUN range.
var localCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"::/127",
	"fc00::/7",
	"fe80::/10",
}
