package client

import "net/netip"

// shownAddr is how the takeover message and -list's PEER show an address
// (bootstrap.md §9.1). IPv4 goes whole. An IPv6 address whose RFC 5952
// form writes more than four groups shows its first two and last two
// written groups with … between: four groups, as IPv4 shows. The first
// two say roughly which network it is on and the last two tell hosts
// apart [D: Dan, 2026-11-27]. The cut works on the RFC 5952 text, so a
// :: in a kept part stays and no zero it collapsed comes back. The full
// address stays in the log.
func shownAddr(a netip.Addr) string {
	a = a.Unmap()
	full := a.String()
	if !a.Is6() {
		return full
	}
	// The start and end of each group the text writes; :: writes none.
	var starts, ends []int
	for i := 0; i < len(full); i++ {
		if full[i] == ':' {
			continue
		}
		j := i
		for j < len(full) && full[j] != ':' {
			j++
		}
		starts, ends = append(starts, i), append(ends, j)
		i = j
	}
	n := len(starts)
	if n <= 4 {
		return full
	}
	return full[:ends[1]] + "…" + full[starts[n-2]:]
}
