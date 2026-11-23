package buildinfo

import "testing"

func TestText(t *testing.T) {
	got := Text()
	want := "warp-mihomo dev\nrevision unknown\nbuilt unknown\n"
	if got != want {
		t.Fatalf("Text() = %q, want %q", got, want)
	}
}
