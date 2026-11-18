// Package reload swaps the proxy map without ApplyConfig.
// ApplyConfig suspends the tunnel and drops new flows. ReCreateTun also
// tears the NIC down when the tun block changes. A map swap leaves the TUN
// and already-dialed MASQUE sessions in place; only later connections use
// the new endpoint addresses.
package reload

import (
	"context"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	_ "github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"

	"warp-mihomo/internal/pool"
)

// Prepare parses the next proxies and inserts the new ones into the live map
// without changing warp-pool. New exits can dial their front by name. The
// returned restore puts the previous map back.
//
// config.Parse is intentionally not used. It temporarily rewrites process-global
// dialer state, including routing-mark, and auto-redirect uses that mark to keep
// the front's own sockets out of the TUN.
func Prepare(raw []byte) (cfg *config.Config, restore func(), err error) {
	cfg, err = parseProxyConfig(raw)
	if err != nil {
		return nil, nil, err
	}
	previous := cloneProxies(tunnel.Proxies())
	merged := cloneProxies(previous)
	for name, proxy := range cfg.Proxies {
		if _, exists := previous[name]; exists {
			continue
		}
		merged[name] = proxy
	}
	tunnel.UpdateProxies(merged, tunnel.Providers())
	restore = func() {
		tunnel.UpdateProxies(previous, tunnel.Providers())
		closeNew(cfg, previous)
	}
	return cfg, restore, nil
}
func parseProxyConfig(raw []byte) (*config.Config, error) {
	rawCfg, err := config.UnmarshalRawConfig(raw)
	if err != nil {
		return nil, err
	}
	proxies := map[string]C.Proxy{
		"DIRECT":      adapter.NewProxy(outbound.NewDirect()),
		"REJECT":      adapter.NewProxy(outbound.NewReject()),
		"REJECT-DROP": adapter.NewProxy(outbound.NewRejectDrop()),
		"COMPATIBLE":  adapter.NewProxy(outbound.NewCompatible()),
		"PASS":        adapter.NewProxy(outbound.NewPass()),
		"PASS-RULE":   adapter.NewProxy(outbound.NewPassRule()),
	}
	providers := make(map[string]P.ProxyProvider)
	names := make([]string, 0, len(rawCfg.Proxy))
	for idx, mapping := range rawCfg.Proxy {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", idx, err)
		}
		if _, exists := proxies[proxy.Name()]; exists {
			return nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		names = append(names, proxy.Name())
	}
	for idx, mapping := range rawCfg.ProxyGroup {
		group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providers, names, nil)
		if err != nil {
			return nil, fmt.Errorf("proxy group %d: %w", idx, err)
		}
		if _, exists := proxies[group.Name()]; exists {
			return nil, fmt.Errorf("proxy group %s: the duplicate name", group.Name())
		}
		proxies[group.Name()] = adapter.NewProxy(group)
	}
	return &config.Config{Proxies: proxies, Providers: providers}, nil
}

// Promote points warp-pool at the parsed group. Call it only after Prepare
// and a successful dial of one new exit.
func Promote(cfg *config.Config) error {
	group, ok := cfg.Proxies[pool.PoolName]
	if !ok {
		return fmt.Errorf("config has no %s group", pool.PoolName)
	}
	merged := cloneProxies(tunnel.Proxies())
	merged[pool.PoolName] = group
	tunnel.UpdateProxies(merged, cfg.Providers)
	for _, provider := range cfg.Providers {
		if provider.Type() != P.Proxy {
			continue
		}
		if err := provider.Initial(); err != nil {
			return err
		}
	}
	return nil
}

// Probe dials exits until one reaches the test URL. The front comes up as
// that exit's dialer.
func Probe(cfg *config.Config, exits []string) error {
	ranges, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		return err
	}
	var last error
	for _, name := range exits {
		proxy, ok := cfg.Proxies[name]
		if !ok {
			return fmt.Errorf("missing proxy %s", name)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		_, last = proxy.URLTest(ctx, "https://www.gstatic.com/generate_204", ranges)
		cancel()
		if last == nil {
			return nil
		}
	}
	if last == nil {
		last = fmt.Errorf("no exit to probe")
	}
	return last
}

func cloneProxies(in map[string]C.Proxy) map[string]C.Proxy {
	out := make(map[string]C.Proxy, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func closeNew(cfg *config.Config, previous map[string]C.Proxy) {
	for name, proxy := range cfg.Proxies {
		if _, exists := previous[name]; exists {
			continue
		}
		_ = proxy.Close()
	}
}

// Drop closes proxies and removes them from the live map. Call it only when
// those names no longer appear in connection chains.
func Drop(names []string) {
	merged := cloneProxies(tunnel.Proxies())
	for _, name := range names {
		proxy, ok := merged[name]
		if !ok {
			continue
		}
		_ = proxy.Close()
		delete(merged, name)
	}
	tunnel.UpdateProxies(merged, tunnel.Providers())
}
