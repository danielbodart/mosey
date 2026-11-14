// Command mosey is the one mosey binary: the client, `mosey host`, which
// logs in with the system ssh, starts `mosey --serve` there, and then talks
// to it over UDP, roaming with the network and drawing the screen the
// server sends; and the server, `mosey --serve`, with its roles (server.go).
//
// The binary is one file for both because D7 copies the client's own build
// over as the server, so the copy is always the very file the client runs.
package main
