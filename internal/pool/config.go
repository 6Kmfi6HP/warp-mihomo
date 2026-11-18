package pool

import (
	"fmt"
	"strconv"
	"strings"
)

// YAML renders a mihomo config. The front dials MASQUE directly. Each exit
// sets dialer-proxy to the front, and the load-balance group contains only
// exits. TUN auto-route takes the network namespace; auto-detect-interface
// binds the front's own dial to the container NIC so it does not re-enter TUN.
func YAML(devices []Device, tun bool) ([]byte, error) {
	if len(devices) < 2 || devices[0].Role != RoleFront {
		return nil, fmt.Errorf("yaml wants the front first, then exits")
	}
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
	b.WriteString("  proxy-server-nameserver:\n")
	b.WriteString("    - 1.1.1.1\n")
	b.WriteString("\n")
	b.WriteString("proxies:\n")
	front := devices[0].Name
	for i, d := range devices {
		dialer := ""
		if i > 0 {
			dialer = front
		}
		if err := writeProxy(&b, d, dialer); err != nil {
			return nil, err
		}
	}
	b.WriteString("\n")
	b.WriteString("proxy-groups:\n")
	b.WriteString("  - name: " + PoolName + "\n")
	b.WriteString("    type: load-balance\n")
	b.WriteString("    strategy: round-robin\n")
	b.WriteString("    lazy: true\n")
	b.WriteString("    url: https://www.gstatic.com/generate_204\n")
	b.WriteString("    expected-status: \"204\"\n")
	b.WriteString("    interval: 300\n")
	b.WriteString("    timeout: 5000\n")
	b.WriteString("    proxies:\n")
	for _, d := range devices[1:] {
		b.WriteString("      - " + d.Name + "\n")
	}
	b.WriteString("\n")
	b.WriteString("rules:\n")
	b.WriteString("  - MATCH," + PoolName + "\n")
	return []byte(b.String()), nil
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
