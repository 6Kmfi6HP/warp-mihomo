package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"warp-mihomo/internal/buildinfo"
	"warp-mihomo/internal/health"
	"warp-mihomo/internal/pool"
	"warp-mihomo/internal/reload"
	"warp-mihomo/internal/warp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2:])
	case "enroll":
		err = enroll(os.Args[2:])
	case "health":
		err = doHealth()
	case "version":
		if len(os.Args) != 2 {
			usage()
			os.Exit(2)
		}
		fmt.Print(buildinfo.Text())
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: warp-mihomo run|enroll|health [-data dir] [-fronts-h3 n] [-exits-h3 n] [-fronts-h2 n] [-exits-h2 n] [-tun]")
	fmt.Fprintln(os.Stderr, "       warp-mihomo version")
}

type runOptions struct {
	data     string
	frontsH3 int
	exitsH3  int
	frontsH2 int
	exitsH2  int
	tun      bool
}

func (o runOptions) spec() pool.Spec {
	return pool.Spec{
		FrontsH3: o.frontsH3,
		ExitsH3:  o.exitsH3,
		FrontsH2: o.frontsH2,
		ExitsH2:  o.exitsH2,
	}
}

func run(args []string) error {
	opts, err := flags("run", args)
	if err != nil {
		return err
	}
	if os.Getenv("SKIP_SYSTEM_IPV6_CHECK") == "" {
		os.Setenv("SKIP_SYSTEM_IPV6_CHECK", "1")
	}
	direct, err := pool.LoadDirect(opts.data, os.Getenv("WARP_DIRECT"), os.Getenv("WARP_DIRECT_FILE"))
	if err != nil {
		return err
	}
	unlock, err := pool.Lock(opts.data)
	if err != nil {
		return err
	}
	defer unlock()
	devices, err := pool.Ensure(opts.data, opts.spec(), enrollOne)
	if err != nil {
		return err
	}
	raw, err := pool.YAMLWithDirect(devices, opts.tun, direct)
	if err != nil {
		return err
	}
	path := filepath.Join(opts.data, "mihomo.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	C.SetHomeDir(opts.data)
	fmt.Fprintf(os.Stderr, "mihomo %s devices %d (h3: %d fronts/%d exits, h2: %d fronts/%d exits) tun %t\n", C.Version, len(devices), opts.frontsH3, opts.exitsH3, opts.frontsH2, opts.exitsH2, opts.tun)
	if len(direct.Domains) > 0 || len(direct.CIDRs) > 0 || len(direct.Rules) > 0 {
		fmt.Fprintf(os.Stderr, "direct bypass: %d domains, %d cidrs, %d rules\n", len(direct.Domains), len(direct.CIDRs), len(direct.Rules))
	}
	if err := hub.Parse(raw); err != nil {
		return err
	}
	defer executor.Shutdown()
	interval, err := rotateEvery()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if interval > 0 {
		go rotateLoop(ctx, opts, interval, devices, direct)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	return nil
}

func enroll(args []string) error {
	opts, err := flags("enroll", args)
	if err != nil {
		return err
	}
	unlock, err := pool.Lock(opts.data)
	if err != nil {
		return err
	}
	defer unlock()
	devices, err := pool.Ensure(opts.data, opts.spec(), enrollOne)
	if err != nil {
		return err
	}
	fmt.Printf("enrolled %d devices\n", len(devices))
	return nil
}

func doHealth() error {
	line, err := health.Check()
	if err != nil {
		return err
	}
	fmt.Println(line)
	return nil
}

var (
	enrollMu   sync.Mutex
	lastEnroll time.Time
)

// fallbackRegURL is set from -fallback-reg-url / WARP_FALLBACK_REG_URL.
// Empty disables the fallback.
var fallbackRegURL = warp.DefaultFallbackRegURL

func enrollOne(name string) (warp.Identity, error) {
	enrollMu.Lock()
	defer enrollMu.Unlock()
	const minGap = 500 * time.Millisecond
	if !lastEnroll.IsZero() {
		if wait := minGap - time.Since(lastEnroll); wait > 0 {
			time.Sleep(wait)
		}
	}
	var err error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 15 * time.Second)
		}
		var id warp.Identity
		id, err = warp.Register(context.Background(), name)
		lastEnroll = time.Now()
		if err == nil {
			return id, nil
		}
		if !strings.Contains(err.Error(), "cloudflare 429") {
			return warp.Identity{}, err
		}
		fmt.Fprintf(os.Stderr, "enroll %s rate-limited, retrying (%d/2)...\n", name, attempt+1)
		if fallbackRegURL == "" {
			continue
		}
		fbID, fbErr := warp.RegisterFallback(context.Background(), fallbackRegURL, name)
		if fbErr == nil {
			fmt.Fprintf(os.Stderr, "enroll %s enrolled via fallback registration\n", name)
			return fbID, nil
		}
		fmt.Fprintf(os.Stderr, "enroll %s fallback failed: %v\n", name, fbErr)
	}
	return warp.Identity{}, err
}

func flags(name string, args []string) (runOptions, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", getenv("WARP_DATA", "data"), "state directory")
	frontsH3 := fs.Int("fronts-h3", getenvInt("WARP_FRONTS_H3", 2), "H3 front devices in the H3 front pool")
	exitsH3 := fs.Int("exits-h3", getenvInt("WARP_EXITS_H3", 3), "H3 exit devices in warp-pool")
	frontsH2 := fs.Int("fronts-h2", getenvInt("WARP_FRONTS_H2", 1), "H2 front devices in the H2 front pool")
	exitsH2 := fs.Int("exits-h2", getenvInt("WARP_EXITS_H2", 1), "H2 exit devices in warp-pool")
	tun := fs.Bool("tun", getenvBool("WARP_TUN", true), "enable TUN")
	fallback := fs.String("fallback-reg-url", getenv("WARP_FALLBACK_REG_URL", warp.DefaultFallbackRegURL), "browser-style registration endpoint used when Cloudflare answers 429 (\"off\" disables)")
	if err := fs.Parse(args); err != nil {
		return runOptions{}, err
	}
	fallbackRegURL = normalizeFallback(*fallback)
	return runOptions{
		data:     *data,
		frontsH3: *frontsH3,
		exitsH3:  *exitsH3,
		frontsH2: *frontsH2,
		exitsH2:  *exitsH2,
		tun:      *tun,
	}, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// normalizeFallback maps the disable spellings of -fallback-reg-url to "".
func normalizeFallback(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "off", "none", "disabled", "0":
		return ""
	}
	return strings.TrimSpace(v)
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getenvBool(key string, fallback bool) bool {
	switch os.Getenv(key) {
	case "":
		return fallback
	case "0", "false", "no":
		return false
	default:
		return true
	}
}

type retiredGen struct {
	gen   int
	names []string
	exits []string
}

func rotateEvery() (time.Duration, error) {
	switch v := os.Getenv("WARP_ROTATE"); v {
	case "":
		return time.Hour, nil
	case "0":
		return 0, nil
	default:
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("WARP_ROTATE: %w", err)
		}
		if d < 0 {
			return 0, fmt.Errorf("WARP_ROTATE must be >= 0")
		}
		return d, nil
	}
}

func rotateLoop(ctx context.Context, opts runOptions, interval time.Duration, current []pool.Device, direct pool.DirectRules) {
	tick := time.NewTicker(interval)
	reap := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	defer reap.Stop()
	var retired []retiredGen
	fmt.Fprintf(os.Stderr, "rotate every %s\n", interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			next, hold, err := rotateOnce(opts, current, direct)
			if err != nil {
				fmt.Fprintf(os.Stderr, "rotate: %v\n", err)
				continue
			}
			current = next
			if hold != nil {
				retired = append(retired, *hold)
			}
		case <-reap.C:
			retired = reapRetired(opts.data, retired)
		}
	}
}

func rotateOnce(opts runOptions, current []pool.Device, direct pool.DirectRules) ([]pool.Device, *retiredGen, error) {
	next, err := pool.Rotate(opts.data, opts.spec(), enrollOne)
	if err != nil {
		return nil, nil, err
	}
	raw, err := pool.YAMLWithDirect(next, opts.tun, direct)
	if err != nil {
		return nil, nil, rollback(opts.data, current, next, err)
	}
	cfg, restore, err := reload.Prepare(raw)
	if err != nil {
		return nil, nil, rollback(opts.data, current, next, err)
	}
	plan, err := pool.SplitPlan(next)
	if err != nil {
		restore()
		return nil, nil, rollback(opts.data, current, next, err)
	}
	if err := reload.ProbeTracks(cfg, buildProbeTracks(plan)); err != nil {
		restore()
		return nil, nil, rollback(opts.data, current, next, err)
	}
	if err := pool.Activate(opts.data, plan.Gen); err != nil {
		restore()
		return nil, nil, rollback(opts.data, current, next, err)
	}
	if err := reload.Promote(cfg); err != nil {
		restore()
		return nil, nil, rollback(opts.data, current, next, err)
	}
	if err := os.WriteFile(filepath.Join(opts.data, "mihomo.yaml"), raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "rotate: wrote live proxies but not mihomo.yaml: %v\n", err)
	}
	oldPlan, _ := pool.SplitPlan(current)
	oldGen := oldPlan.Gen
	oldGroupNames := oldPlan.FrontGroupNames()
	old := make([]string, 0, len(current)+len(oldGroupNames))
	oldExits := make([]string, 0, len(current))
	for i, dev := range current {
		old = append(old, dev.Name)
		if dev.Role == pool.RoleExit {
			oldExits = append(oldExits, dev.Name)
		}
		nxt := next[min(i, len(next)-1)]
		fmt.Fprintf(os.Stderr, "rotate %s %s -> %s %s\n", dev.Name, net.JoinHostPort(dev.Server, strconv.Itoa(dev.Port)), nxt.Name, net.JoinHostPort(nxt.Server, strconv.Itoa(nxt.Port)))
	}
	old = append(old, oldGroupNames...)
	fmt.Fprintf(os.Stderr, "rotate generation %d serving, generation %d draining\n", plan.Gen, oldGen)
	return next, &retiredGen{gen: oldGen, names: old, exits: oldExits}, nil
}

func buildProbeTracks(plan pool.Plan) []reload.ProbeTrack {
	var tracks []reload.ProbeTrack
	if len(plan.FrontsH3) > 0 {
		tracks = append(tracks, reload.ProbeTrack{
			Name:   pool.NetworkH3,
			Fronts: deviceNames(plan.FrontsH3),
			Exits:  deviceNames(plan.ExitsH3),
		})
	}
	if len(plan.FrontsH2) > 0 {
		tracks = append(tracks, reload.ProbeTrack{
			Name:   pool.NetworkH2,
			Fronts: deviceNames(plan.FrontsH2),
			Exits:  deviceNames(plan.ExitsH2),
		})
	}
	return tracks
}

func deviceNames(devices []pool.Device) []string {
	names := make([]string, len(devices))
	for i, d := range devices {
		names[i] = d.Name
	}
	return names
}

func rollback(data string, current, failed []pool.Device, cause error) error {
	if len(current) == 0 || len(failed) == 0 {
		return cause
	}
	if err := pool.Activate(data, current[0].Generation); err != nil {
		return fmt.Errorf("%w (restore generation: %v)", cause, err)
	}
	if err := pool.ForgetGeneration(data, failed[0].Generation); err != nil {
		return fmt.Errorf("%w (forget failed generation: %v)", cause, err)
	}
	return cause
}

func reapRetired(data string, retired []retiredGen) []retiredGen {
	if len(retired) == 0 {
		return retired
	}
	kept := retired[:0]
	chains := liveChains()
	for _, hold := range retired {
		if !pool.GenerationIdle(hold.exits, chains) {
			kept = append(kept, hold)
			continue
		}
		reload.Drop(hold.names)
		if err := pool.ForgetGeneration(data, hold.gen); err != nil {
			fmt.Fprintf(os.Stderr, "rotate: forget generation %d: %v\n", hold.gen, err)
			kept = append(kept, hold)
			continue
		}
		fmt.Fprintf(os.Stderr, "rotate: closed idle generation %d\n", hold.gen)
	}
	return kept
}

func liveChains() [][]string {
	snap := statistic.DefaultManager.Snapshot()
	if snap == nil {
		return nil
	}
	out := make([][]string, 0, len(snap.Connections))
	for _, conn := range snap.Connections {
		if conn == nil {
			continue
		}
		out = append(out, append([]string(nil), conn.Chain...))
	}
	return out
}
