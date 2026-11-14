// Package bootstrap is the SSH part of starting a session (D6, D20, D25):
// the system ssh, with the user's own config, runs `mosey server` on the far
// host; the client writes one line to its stdin and reads one line back
// from its stdout.
//
//	client -> server (stdin)   ClientLine: the client's one-shot public key,
//	                           window size, TERM and locale
//	server -> client (stdout)  CredentialLine: address, port, credential id,
//	                           session id, PSK, the server's one-shot key
//
// SSH only has to be authentic, not confidential (D20): nothing on either
// line lets a reader impersonate either side. Lines are printable ASCII,
// fields base64url without padding, so a shell's echo or a session recorder
// cannot mangle them. stdout may carry other text before the line (a motd,
// a shell's chatter); the client skips it, within a bound.
//
// Both parsers are fuzzed: the stdin line is parsed by the spawner, which
// is unsandboxed, and the stdout line comes from a host SSH vouched for but
// that may still be hostile.
package bootstrap
