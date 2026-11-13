package sim

import (
	"os"
	"testing"
	"time"

	"mosey.spike/s6-prediction/predict"
	"mosey.spike/s6-prediction/trace"
)

// TestNoPasswordGlyphShown replays every recorded `read -s` segment (bash and
// zsh: canonical no-echo, covered by the echo-off bit; fish: raw mode with
// a ● mask, covered only by the epoch rules) and asserts that no predicted
// glyph of a password key is ever displayed. It also checks the replay is
// deterministic (same seed, same result).
func TestNoPasswordGlyphShown(t *testing.T) {
	profiles := []Profile{
		{Name: "lan", RTT: 5 * time.Millisecond, Jitter: time.Millisecond},
		{Name: "lossy", RTT: 100 * time.Millisecond, Loss: 0.29},
		{Name: "evdo", RTT: 450 * time.Millisecond, Jitter: 100 * time.Millisecond, Loss: 0.01},
	}
	rebase := predict.Mosey()
	rebase.Recovery = predict.RecoverRebase
	for _, name := range []string{"bash", "zsh-plain", "zsh-full", "fish"} {
		tr, err := trace.Load("../traces/" + name + ".json.gz")
		if err != nil {
			if os.IsNotExist(err) {
				t.Skip("traces not present")
			}
			t.Fatal(err)
		}
		for _, p := range profiles {
			for _, cfg := range []predict.Config{predict.Mosey(), rebase} {
				r := RunOpts(tr, p, cfg, 1000, Options{EchoAck: EchoAckExtraUnlessEchoOff})
				secret := 0
				for _, k := range r.Keys {
					if k.Secret {
						secret++
					}
				}
				if secret == 0 {
					t.Fatalf("%s: no password keys found in trace", name)
				}
				if r.SecretKeysShown != 0 {
					t.Errorf("%s/%s recovery=%d: %d password keys displayed", name, p.Name, cfg.Recovery, r.SecretKeysShown)
				}
				r2 := RunOpts(tr, p, cfg, 1000, Options{EchoAck: EchoAckExtraUnlessEchoOff})
				if r2.EngineKills != r.EngineKills || r2.EngineVisible != r.EngineVisible || r2.SecretCellsShown != r.SecretCellsShown {
					t.Errorf("%s/%s: replay not deterministic", name, p.Name)
				}
			}
		}
	}
}
