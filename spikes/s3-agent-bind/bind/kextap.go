package bind

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Option (a): golang.org/x/crypto/ssh does not expose the server's
// signature over the exchange hash. It is, however, sent in the clear (the
// first key exchange runs before any NEWKEYS), so a net.Conn wrapper can
// copy the bytes the server sends until its first NEWKEYS and pull K_S and
// the signature out of the ECDH reply (message 31). The session id comes
// from ssh.Conn.SessionID(). Restrict the client's KeyExchanges to ECDH or
// hybrid-ML-KEM methods: in diffie-hellman-group-exchange, 31 is a
// different message.

type TapConn struct {
	net.Conn
	mu   sync.Mutex
	buf  bytes.Buffer
	done bool
}

const maxTap = 64 << 10

func (t *TapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.mu.Lock()
	if !t.done && n > 0 {
		t.buf.Write(p[:n])
		if t.buf.Len() > maxTap {
			t.done = true
		}
	}
	t.mu.Unlock()
	return n, err
}

// KexReply parses the tapped server bytes: the version line, then
// cleartext binary packets up to NEWKEYS; returns K_S and the signature
// blob from message 31.
func (t *TapConn) KexReply() (hostKey, sig []byte, err error) {
	t.mu.Lock()
	t.done = true
	b := append([]byte(nil), t.buf.Bytes()...)
	t.mu.Unlock()
	// Skip lines until the SSH- identification line (RFC 4253 §4.2).
	for {
		i := bytes.Index(b, []byte("\r\n"))
		if i < 0 {
			return nil, nil, errors.New("tap: no version line")
		}
		line := b[:i]
		b = b[i+2:]
		if bytes.HasPrefix(line, []byte("SSH-")) {
			break
		}
	}
	for len(b) >= 5 {
		plen := binary.BigEndian.Uint32(b)
		if uint64(plen)+4 > uint64(len(b)) || plen < 1 {
			break
		}
		pad := int(b[4])
		if pad+1 > int(plen) {
			return nil, nil, errors.New("tap: bad padding")
		}
		payload := b[5 : 4+int(plen)-pad]
		b = b[4+plen:]
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case 31:
			r := &rd{b: payload[1:]}
			ks, _, s := r.str(), r.str(), r.str()
			if r.err != nil {
				return nil, nil, errors.New("tap: malformed kex reply")
			}
			return ks, s, nil
		case 21:
			return nil, nil, errors.New("tap: NEWKEYS before a kex reply")
		}
	}
	return nil, nil, errors.New("tap: no kex reply seen")
}

// BindFromClientConn assembles the triple for option (a).
func BindFromClientConn(t *TapConn, c ssh.Conn) (*Bind, error) {
	ks, sig, err := t.KexReply()
	if err != nil {
		return nil, err
	}
	k, err := ssh.ParsePublicKey(ks)
	if err != nil {
		return nil, err
	}
	b := &Bind{HostKey: k, SID: c.SessionID(), Sig: sig}
	return b, b.Verify()
}
