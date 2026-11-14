package ipc

import "os"

// Message is one IPC message.
type Message interface{ message() }

// Start is the spawner's first message to proto: what the client sent over
// SSH stdin, and the fds proto needs. proto mints the credential, since
// only proto holds keys (S4).
type Start struct {
	ClientPublic []byte
	Cols, Rows   int
	UDP          *os.File // the bound socket
	PTY          *os.File // the master
}

// Credential is proto's answer to Start: the line the spawner prints on
// stdout, already encoded, so the spawner never sees a key it must handle.
type Credential struct{ Line []byte }

// Resize tells emu the window size changed. proto sets the pty's own size
// itself, with TIOCSWINSZ on the master, which its policy allows (S4 §5).
type Resize struct{ Cols, Rows int }

// Output is program output for emu.
type Output struct{ Data []byte }

// Update is emu's answer to Output or Resize: a screen diff from the last
// Update to now, which proto applies to its own copy of the grid with the
// same validating decoder the client uses.
type Update struct{ Diff []byte }

// Replies are bytes emu wants written to the program. proto writes them
// only if they match the reply grammar (S4 §5.3).
type Replies struct{ Data []byte }

// Exit tells the spawner the session is over and why.
type Exit struct{ Reason string }

func (Start) message()      {}
func (Credential) message() {}
func (Resize) message()     {}
func (Output) message()     {}
func (Update) message()     {}
func (Replies) message()    {}
func (Exit) message()       {}

// Marshal encodes m without its fds.
func Marshal(m Message) ([]byte, error) {
	panic("TODO slice 1")
}

// Parse decodes one message, refusing anything outside its fixed layout.
func Parse(b []byte) (Message, error) {
	panic("TODO slice 1")
}
