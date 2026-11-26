package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
	fmt.Fprintln(os.Stderr, "usage: warp-mihomo run|enroll|health [-data dir] [-fronts n] [-exits n] [-tun]")
	fmt.Fprintln(os.Stderr, "       warp-mihomo version")
}

type runOptions struct {
	data   string
	fronts int
	exits  int
	tun    bool
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
	devices, err := pool.Ensure(opts.data, opts.fronts, opts.exits, enrollOne)
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
	fmt.Fprintf(os.Stderr, "mihomo %s devices %d (fronts %d, exits %d) tun %t\n", C.Version, len(devices), opts.fronts, opts.exits, opts.tun)
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
	devices, err := pool.Ensure(opts.data, opts.fronts, opts.exits, enrollOne)
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

func enrollOne(name string) (warp.Identity, error) {
	return warp.Register(context.Background(), name)
}

func flags(name string, args []string) (runOptions, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", getenv("WARP_DATA", "data"), "state directory")
	fronts := fs.Int("fronts", getenvInt("WARP_FRONTS", 1), "front devices in the front pool")
	exits := fs.Int("exits", getenvInt("WARP_EXITS", 3), "exit devices in the exit pool")
	tun := fs.Bool("tun", getenvBool("WARP_TUN", true), "enable TUN")
	if err := fs.Parse(args); err != nil {
		return runOptions{}, err
	}
	return runOptions{
		data:   *data,
		fronts: *fronts,
		exits:  *exits,
		tun:    *tun,
	}, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
	next, err := pool.Rotate(opts.data, opts.fronts, opts.exits, enrollOne)
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
	fronts, exits, nextGen, err := pool.SplitRoles(next)
	if err != nil {
		restore()
		return nil, nil, rollback(opts.data, current, next, err)
	}
	probeFronts := deviceNames(fronts)
	probeExits := deviceNames(exits)
	if err := reload.Probe(cfg, probeFronts, probeExits); err != nil {
		restore()
		return nil, nil, rollback(opts.data, current, next, err)
	}
	if err := pool.Activate(opts.data, nextGen); err != nil {
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
	oldGen := current[0].Generation
	old := make([]string, 0, len(current)+1)
	oldExits := make([]string, 0, len(current))
	for i, dev := range current {
		old = append(old, dev.Name)
		if dev.Role == pool.RoleExit {
			oldExits = append(oldExits, dev.Name)
		}
		nxt := next[min(i, len(next)-1)]
		fmt.Fprintf(os.Stderr, "rotate %s %s:%d -> %s %s:%d\n", dev.Name, dev.Server, dev.Port, nxt.Name, nxt.Server, nxt.Port)
	}
	old = append(old, pool.FrontGroupName(oldGen))
	fmt.Fprintf(os.Stderr, "rotate generation %d serving, generation %d draining\n", nextGen, oldGen)
	return next, &retiredGen{gen: oldGen, names: old, exits: oldExits}, nil
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
