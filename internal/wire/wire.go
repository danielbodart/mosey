package wire

const (
	// MaxDatagram is the largest UDP payload mosey ever sends (D5).
	MaxDatagram = 1232

	// MaxHandshake is the largest UDP payload of any handshake or rekey
	// message (D5). A message that would be bigger is split, as REKEY_INIT
	// is (D20).
	MaxHandshake = 1200
)
