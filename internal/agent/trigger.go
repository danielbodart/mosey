package agent

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TriggerTimeout bounds the launcher's trigger (bootstrap.md §8, §11).
const TriggerTimeout = 5 * time.Second

// Trigger is the launcher's half of the capture (bootstrap.md §8,
// "Server"): it opens sshd's forwarded agent socket, which makes the
// client's ssh connect to its capture socket and send its bind, asks for
// identities, reads the one answer, and closes, so the capture sees EOF.
func Trigger(ctx context.Context, sock string) error {
	ctx, cancel := context.WithTimeout(ctx, TriggerTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return fmt.Errorf("connecting to the forwarded agent: %w", err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(frame(msgRequestIdentities)); err != nil {
		return fmt.Errorf("asking the forwarded agent for identities: %w", err)
	}
	if _, err := readFrame(c, MaxTriggerReply); err != nil {
		return fmt.Errorf("reading the forwarded agent's answer: %w", err)
	}
	return nil
}
