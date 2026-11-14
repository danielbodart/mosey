package nocore

// Process makes the calling process leave no core dump and unreadable to
// the user's other processes, where the system allows: for the client,
// proto and emu, first of all, before they generate, receive or read any
// secret (threat-model.md §4.10).
func Process() error {
	if err := notDumpable(); err != nil && !unsupported(err) {
		return err
	}
	return noCoreLimit()
}

// NotDumpable is PR_SET_DUMPABLE 0 alone, without the core rlimit a child
// would inherit: for the launcher and the spawner, before they read the
// credential line (server.md §2.1). Off Linux it is errors.ErrUnsupported.
func NotDumpable() error {
	return notDumpable()
}
