package sandbox

import (
	"strings"
	"testing"
)

func TestProtosProfileIsTheMeasuredOneWithItsOwnPort(t *testing.T) {
	got, err := Profile(Proto, Params{UDPPort: 60001})
	if err != nil {
		t.Fatal(err)
	}
	want := `(version 1)
(deny default)
(allow network-inbound (local udp "*:60001"))
(allow network-outbound (local udp "*:60001"))
(allow file-ioctl (ioctl-command TIOCSWINSZ))
(allow sysctl-read (sysctl-name "hw.ncpu"))
(deny process-info*)
`
	if got != want {
		t.Errorf("proto's profile is\n%s\nnot\n%s", got, want)
	}
}

func TestEmusProfileAllowsOnlyTheCPUCount(t *testing.T) {
	got, err := Profile(Emu, Params{UDPPort: 60001})
	if err != nil {
		t.Fatal(err)
	}
	want := `(version 1)
(deny default)
(allow sysctl-read (sysctl-name "hw.ncpu"))
(deny process-info*)
`
	if got != want {
		t.Errorf("emu's profile is\n%s\nnot\n%s", got, want)
	}
}

func TestAPortOutOfRangeNeverReachesProtosProfile(t *testing.T) {
	for _, port := range []int{0, -1, 65536, 1 << 40} {
		if p, err := Profile(Proto, Params{UDPPort: port}); err == nil {
			t.Errorf("port %d made a profile:\n%s", port, p)
		}
	}
	for _, port := range []int{1, 65535} {
		if p, err := Profile(Proto, Params{UDPPort: port}); err != nil || !strings.Contains(p, `"*:`) {
			t.Errorf("port %d: %v", port, err)
		}
	}
}

func TestAnUnknownRoleHasNoProfile(t *testing.T) {
	if _, err := Profile(Role(0), Params{UDPPort: 1}); err == nil {
		t.Error("role 0 has a profile")
	}
}
