package server

import "testing"

// The hold is a quarter of the window at the screen's width
// (docs/spec/screen.md §2.5): 250 lines up to 200 columns, fewer beyond,
// as the window holds fewer.
func TestTheHoldIsAQuarterOfTheWindowAtTheScreensWidth(t *testing.T) {
	for cols, want := range map[int]int{0: 250, 80: 250, 200: 250, 400: 125, 1000: 50} {
		if got := holdLines(cols); got != want {
			t.Errorf("holdLines(%d) = %d, want %d", cols, got, want)
		}
	}
}

// What the client lacks is counted in the window the screen holds: a
// client new to the session, whose acknowledged history is empty, lacks
// the window and no more, and one that has everything lacks nothing.
func TestTheClientLacksAtMostTheWindow(t *testing.T) {
	cases := []struct {
		next  uint64
		held  int
		acked uint64
		want  uint64
	}{
		{next: 50_000, held: 1000, acked: 0, want: 1000},
		{next: 50_000, held: 1000, acked: 49_900, want: 100},
		{next: 50_000, held: 1000, acked: 50_000, want: 0},
		{next: 50_000, held: 1000, acked: 60_000, want: 0},
		{next: 10, held: 10, acked: 0, want: 10},
	}
	for _, c := range cases {
		if got := unacknowledged(c.next, c.held, c.acked); got != c.want {
			t.Errorf("unacknowledged(%d, %d, %d) = %d, want %d", c.next, c.held, c.acked, got, c.want)
		}
	}
}
