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
	fmt.Fprintln(os.Stderr, "usage: warp-mihomo run|enroll|health [-data dir] [-exits n] [-tun]")
}

func run(args []string) error {
	data, exits, tun, err := flags("run", args)
	if err != nil {
		return err
	}
	if os.Getenv("SKIP_SYSTEM_IPV6_CHECK") == "" {
		os.Setenv("SKIP_SYSTEM_IPV6_CHECK", "1")
	}
	unlock, err := pool.Lock(data)
	if err != nil {
		return err
	}
	defer unlock()
	devices, err := pool.Ensure(data, exits, enrollOne)
	if err != nil {
		return err
	}
	raw, err := pool.YAML(devices, tun)
	if err != nil {
		return err
	}
	path := filepath.Join(data, "mihomo.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	C.SetHomeDir(data)
	fmt.Fprintf(os.Stderr, "mihomo %s devices %d tun %t\n", C.Version, len(devices), tun)
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
		go rotateLoop(ctx, data, exits, tun, interval, devices)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	return nil
}

func enroll(args []string) error {
	data, exits, _, err := flags("enroll", args)
	if err != nil {
		return err
	}
	unlock, err := pool.Lock(data)
	if err != nil {
		return err
	}
	defer unlock()
	devices, err := pool.Ensure(data, exits, enrollOne)
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

func flags(name string, args []string) (string, int, bool, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	data := fs.String("data", getenv("WARP_DATA", "data"), "state directory")
	exits := fs.Int("exits", getenvInt("WARP_EXITS", 3), "exit devices behind the front")
	tun := fs.Bool("tun", getenvBool("WARP_TUN", true), "enable TUN")
	if err := fs.Parse(args); err != nil {
		return "", 0, false, err
	}
	return *data, *exits, *tun, nil
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

func rotateLoop(ctx context.Context, data string, exits int, tun bool, interval time.Duration, current []pool.Device) {
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
			next, hold, err := rotateOnce(data, exits, tun, current)
			if err != nil {
				fmt.Fprintf(os.Stderr, "rotate: %v\n", err)
				continue
			}
			current = next
			if hold != nil {
				retired = append(retired, *hold)
			}
		case <-reap.C:
			retired = reapRetired(data, retired)
		}
	}
}

func rotateOnce(data string, exits int, tun bool, current []pool.Device) ([]pool.Device, *retiredGen, error) {
	next, err := pool.Rotate(data, exits, enrollOne)
	if err != nil {
		return nil, nil, err
	}
	raw, err := pool.YAML(next, tun)
	if err != nil {
		return nil, nil, rollback(data, current, next, err)
	}
	cfg, restore, err := reload.Prepare(raw)
	if err != nil {
		return nil, nil, rollback(data, current, next, err)
	}
	probe := make([]string, len(next)-1)
	for i, dev := range next[1:] {
		probe[i] = dev.Name
	}
	if err := reload.Probe(cfg, probe); err != nil {
		restore()
		return nil, nil, rollback(data, current, next, err)
	}
	if err := pool.Activate(data, next[0].Generation); err != nil {
		restore()
		return nil, nil, rollback(data, current, next, err)
	}
	if err := reload.Promote(cfg); err != nil {
		restore()
		return nil, nil, rollback(data, current, next, err)
	}
	if err := os.WriteFile(filepath.Join(data, "mihomo.yaml"), raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "rotate: wrote live proxies but not mihomo.yaml: %v\n", err)
	}
	old := make([]string, len(current))
	oldExits := make([]string, 0, len(current)-1)
	for i, dev := range current {
		old[i] = dev.Name
		if dev.Role == pool.RoleExit {
			oldExits = append(oldExits, dev.Name)
		}
		fmt.Fprintf(os.Stderr, "rotate %s %s -> %s %s\n", dev.Name, dev.Server, next[min(i, len(next)-1)].Name, next[min(i, len(next)-1)].Server)
	}
	fmt.Fprintf(os.Stderr, "rotate generation %d serving, generation %d draining\n", next[0].Generation, current[0].Generation)
	return next, &retiredGen{gen: current[0].Generation, names: old, exits: oldExits}, nil
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
