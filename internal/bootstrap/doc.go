// Package bootstrap is the SSH part of starting a session (D6, D20, D25),
// as docs/spec/bootstrap.md specifies it: the system ssh, with the user's
// own config, runs `mosey --serve` on the far host; the client writes one
// line to its stdin and reads one line back from its stdout.
//
//	client -> server (stdin)   ClientLine: the client's one-shot public key,
//	                           window size, TERM and locale
//	server -> client (stdout)  CredentialLine: address, port, credential id,
//	                           session id, PSK, the server's one-shot key
//	                           or ErrorLine: why the server refused
//
// SSH only has to be authentic, not confidential (D20): nothing on either
// line lets a reader impersonate either side. Lines are printable ASCII,
// fields base64url without padding, so a shell's echo or a session recorder
// cannot mangle them, and every parser is canonical: it accepts a line only
// if writing back what it read gives the same bytes. stdout may carry other
// text before the line (a motd, a shell's chatter); ReadCredential skips
// it, within a bound, and Sanitize makes any of it safe to show.
//
// The rest is the client's half of the ssh invocation: ParseSSHOptions
// filters the user's ssh options, SSH.Resolve reads their config with
// `ssh -G`, SSH.Command is the bootstrap ssh itself, and ChooseAddr decides
// where UDP goes. An SSH with no Destination is the local launcher (§2.2):
// the same two lines, with the server run directly and no ssh at all.
//
// Every parser is fuzzed: the stdin line is parsed by the spawner, which
// is unsandboxed, and the stdout line comes from a host SSH vouched for but
// that may still be hostile. The package imports neither handshake nor
// transport: it deals in raw bytes, and internal/client converts.
package bootstrap
