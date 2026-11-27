package main

import (
	"errors"
	"testing"
	"time"
)

func TestReapRetiredTimeoutAndForce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	hold := retiredGen{
		gen:       1,
		names:     []string{"warp-exit-h3-g1-1", "warp-front-h3-g1-1", "warp-front-h3-pool-g1"},
		exits:     []string{"warp-exit-h3-g1-1"},
		retiredAt: now,
	}
	busyChains := [][]string{{"warp-pool", "warp-exit-h3-g1-1"}}

	// Still within drain window with active traffic: keep the generation.
	closedCalls := 0
	droppedCalls := 0
	forgotCalls := 0
	kept := reapRetiredWith(
		t.TempDir(),
		[]retiredGen{hold},
		5*time.Minute,
		now.Add(4*time.Minute),
		false,
		busyChains,
		func(names []string) int { closedCalls++; return len(names) },
		func(names []string) { droppedCalls++ },
		func(string, int) error { forgotCalls++; return nil },
	)
	if len(kept) != 1 || closedCalls != 0 || droppedCalls != 0 || forgotCalls != 0 {
		t.Fatalf("expected busy generation to stay during drain window: kept=%d closed=%d dropped=%d forgot=%d", len(kept), closedCalls, droppedCalls, forgotCalls)
	}

	// Past drain timeout with lingering connection: force-close, drop, and forget.
	var closedNames, droppedNames []string
	var forgotGen int
	kept = reapRetiredWith(
		t.TempDir(),
		[]retiredGen{hold},
		5*time.Minute,
		now.Add(5*time.Minute),
		false,
		busyChains,
		func(names []string) int { closedNames = append([]string(nil), names...); return 1 },
		func(names []string) { droppedNames = append([]string(nil), names...) },
		func(_ string, gen int) error { forgotGen = gen; return nil },
	)
	if len(kept) != 0 {
		t.Fatalf("expected expired generation to be reaped, kept=%+v", kept)
	}
	if len(closedNames) != len(hold.names) || len(droppedNames) != len(hold.names) || forgotGen != 1 {
		t.Fatalf("unexpected reap calls: closed=%v dropped=%v forgotGen=%d", closedNames, droppedNames, forgotGen)
	}

	// Force mode reaps even immediately after retirement.
	closedCalls = 0
	droppedCalls = 0
	forgotCalls = 0
	kept = reapRetiredWith(
		t.TempDir(),
		[]retiredGen{hold},
		5*time.Minute,
		now.Add(time.Second),
		true,
		busyChains,
		func(names []string) int { closedCalls++; return 1 },
		func(names []string) { droppedCalls++ },
		func(string, int) error { forgotCalls++; return nil },
	)
	if len(kept) != 0 || closedCalls != 1 || droppedCalls != 1 || forgotCalls != 1 {
		t.Fatalf("force reap failed: kept=%d closed=%d dropped=%d forgot=%d", len(kept), closedCalls, droppedCalls, forgotCalls)
	}

	// Idle generation reaps without calling closeConns.
	closedCalls = 0
	droppedCalls = 0
	forgotCalls = 0
	kept = reapRetiredWith(
		t.TempDir(),
		[]retiredGen{hold},
		5*time.Minute,
		now.Add(time.Second),
		false,
		nil,
		func(names []string) int { closedCalls++; return 0 },
		func(names []string) { droppedCalls++ },
		func(string, int) error { forgotCalls++; return nil },
	)
	if len(kept) != 0 || closedCalls != 0 || droppedCalls != 1 || forgotCalls != 1 {
		t.Fatalf("idle reap failed: kept=%d closed=%d dropped=%d forgot=%d", len(kept), closedCalls, droppedCalls, forgotCalls)
	}

	// ForgetGeneration failure preserves entry so it can be retried.
	kept = reapRetiredWith(
		t.TempDir(),
		[]retiredGen{hold},
		5*time.Minute,
		now.Add(10*time.Minute),
		false,
		busyChains,
		func(names []string) int { return 1 },
		func(names []string) {},
		func(string, int) error { return errors.New("disk error") },
	)
	if len(kept) != 1 {
		t.Fatalf("expected generation to be retained on forget error, got %d", len(kept))
	}
}

func TestDrainAndRetryTimingHelpers(t *testing.T) {
	if got := drainTimeout(time.Hour); got != defaultDrainTimeout {
		t.Fatalf("drainTimeout(1h) = %s, want %s", got, defaultDrainTimeout)
	}
	if got := drainTimeout(4 * time.Minute); got != 2*time.Minute {
		t.Fatalf("drainTimeout(4m) = %s, want 2m", got)
	}
	if got := drainTimeout(time.Second); got != time.Second {
		t.Fatalf("drainTimeout(1s) = %s, want 1s", got)
	}
	if got := reapInterval(5 * time.Minute); got != defaultReapInterval {
		t.Fatalf("reapInterval(5m) = %s, want %s", got, defaultReapInterval)
	}
	if got := reapInterval(6 * time.Second); got != 2*time.Second {
		t.Fatalf("reapInterval(6s) = %s, want 2s", got)
	}
	if got := rotateRetryDelay(time.Hour); got != defaultRetryDelay {
		t.Fatalf("rotateRetryDelay(1h) = %s, want %s", got, defaultRetryDelay)
	}
	if got := rotateRetryDelay(30 * time.Second); got != 15*time.Second {
		t.Fatalf("rotateRetryDelay(30s) = %s, want 15s", got)
	}
	if got := rotateRetryDelay(0); got != 0 {
		t.Fatalf("rotateRetryDelay(0) = %s, want 0", got)
	}
}
