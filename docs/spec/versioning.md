# Versioning: an open protocol, by elements and features

Owner: **all owners**. Every wire format mosey speaks follows the rules
here; each format's own spec says how, in a table of its elements.

This is how mosey's protocol grows without version numbers going up. It
replaces "a new field or a new value means a new version" (the first
form of PLAN D8 V1), under which every addition was either a bump or a
special case for an optional last field.

## 0. The decision

Dan, 2026-11-17, on why the protocol kept being bumped: "I feel like we
haven't got the design of it quite right if we're just constantly bumping
it and not being able to make additions — it's the difference between a
closed protocol and an open protocol" (an XSD closed content model,
against Schematron's rules that leave the rest open). And: "we're not
going to bump the version. We're going to imagine that this is what we
designed from the start ... we do need to make sure this is secure ... we
need to be explicit about which fields are critical or mandatory and
which aren't so we don't get some kind of security bug." On version
numbers: no minor version; features replace it ("maybe we don't need a
version number ... it's just about the features").

So, as if designed this way from the start (there are no users, and no
compatibility work is done for the builds from before it):

- every element of every message can be skipped by a receiver that does
  not know it (§2);
- every element is either **critical** or not, and an unknown critical
  element makes the receiver refuse the whole message (§3);
- every element is **mandatory** or **optional**, and a message missing a
  mandatory one is refused (§3);
- where a sender must not send something a receiver might not handle, the
  receiver first advertises the **feature** by name (§4);
- each layer keeps one protocol number, all of them **1**, and it now
  names only the envelope: the framing that lets elements be found and
  skipped (§5).

Prior art for the shape: X.509 v3 extensions, each with a critical flag
that a relying party must refuse when it cannot process the extension
[RFC 5280 §4.2]; PNG's chunk names, whose first letter's case says
whether a decoder that does not know the chunk may skip it [RFC 2083
§3.3]; TLS extensions, sent only in answer to an extension the peer
offered [RFC 8446 §4.2].

## 1. Terms

| term | meaning |
|---|---|
| **message** | one unit a parser accepts or refuses whole: a bootstrap line, an attach socket message, a hello, a screen diff, a userinput diff, a channel frame |
| **element** | one named or typed part of a message: a `key=value` field of a line, an element of a hello, an op of a diff, an event, a frame op |
| **envelope** | what a receiver must understand to find the elements and step over the ones it does not know: the line's tag and grammar, a type and its length, the fixed core of a format |
| **protocol number** | the one number per layer that names its envelope (§5) |
| **known** | defined by the spec this build implements |
| **critical** | an element that a receiver which does not know it must not ignore: it refuses the message (§3) |
| **optional / mandatory** | whether a sender may leave the element out; a missing mandatory element is refused |
| **feature** | a named capability a receiver advertises, so a sender knows it may send the elements that belong to it (§4) |

## 2. Must-ignore by default

1. **Self-delimiting.** Every element carries enough of its own framing
   (its key and a value ending at a space; or a type and a length) that a
   receiver can step over it without knowing what it means. Where a
   format's elements are cheap fixed-layout codes that cannot carry a
   length without costing the format its purpose (the screen diff's cell
   ops, `screen.md` §5.1), those codes are the **core**: part of the
   envelope, all critical, and only the protocol number can add one.
   Everything outside the core is length-prefixed.
2. **Unknown and not critical: dropped.** The receiver steps over it and
   acts as if it had not been there. It changes no state of the
   receiver's, and it is dropped **before** any state changes, as part of
   validating the message.
3. **Still bounded.** An unknown element is bounded in size and in count
   by the format (each spec's table says how), and the bound is checked
   before the element is skipped, so unknown elements cost no more than
   known ones could.
4. **Known elements are validated in full**, as before: every bound and
   every grammar, and a known element whose critical marking is not the
   one its spec gives is refused (a sender bug, and the encoding stays
   canonical).
5. **The whole message is validated before anything changes.** Unknown
   elements do not relax this (CLAUDE.md: hostile input is validated in
   full before any state changes).

## 3. Critical and mandatory

**Critical.** An unknown critical element makes the receiver refuse the
whole message, with no state changed, exactly as it refuses a malformed
one. Each format marks criticality on the wire, so a receiver can tell
without knowing the element:

| format | marking |
|---|---|
| bootstrap and attach text lines | a `!` before the key: `!cmd=…` (§6) |
| attach socket messages | bit 3 of the type: `0x40`–`0x47` critical, `0x48`–`0x4F` may be ignored (`server.md` §2.8) |
| hello elements | bit 7 of the type: clear is critical (`transport.md` §3.6) |
| screen diff | the core opcodes are all critical; a property op's bit 5: `0xC0`–`0xDF` critical, `0xE0`–`0xFF` may be ignored (`screen.md` §5.4) |
| userinput events | bit 7 of the kind: clear is critical (`ssp.md` §10.1) |
| channel frame ops | bit 7 of the op: clear is critical (`agent.md` §5.1) |
| transport frame kinds | none: every unknown kind is ignored, so a kind that must not be is sent only after a feature (§4; `transport.md` §4.2) |
| SSP datagram flags, instruction encoding | none needed: they are envelope, each bit saying which fields follow and the encoding how the body reads, so every unknown one is refused (`ssp.md` §3, §4.1) |
| private IPC (spawner, proto, emu) | none: closed, every unknown type refused (§5) |

In the binary formats the marking is a bit of the type, so a type's
criticality is fixed when its number is chosen, never by a flag a sender
could get wrong for one message.

**Which elements are critical.** An element is critical when a receiver
that acted on the rest of the message without it would do something the
sender did not ask for in a way that matters: when it

- **authenticates** (a key, a PSK, a credential id),
- **restricts** or **selects** (which session, which held credential, a
  session's state, where to connect),
- **instructs** (run this command, start in this directory, type this
  text, forward the agent), or
- **changes the meaning** of other elements or of what follows (input
  modes that change how keys are encoded; echo-off, which changes what
  prediction may show).

It is not critical when it **describes** or **advises**: a size the server
clamps anyway, the locale, a name shown to the user, a time, a mark on the
tab, a window title. Ignoring one of those is a lesser display, never a
wrong action. When in doubt, critical: a refusal says so at once, while
an element wrongly ignored fails silently. Each spec's table says, for
every element, which it is and why.

**Mandatory.** A message missing a mandatory element is refused. The
mandatory elements of a message are frozen with its layer's protocol
number: a new mandatory element would make every older sender's message
refused, which is a change of envelope (§5). Every element added under a
protocol number is therefore optional.

## 4. Features by name, not version

Marking covers a receiver that does not know an element: a critical one
is refused, which is safe, and the sender learns nothing until the
refusal. Where that is not good enough, the receiver advertises what it
understands first, and the sender sends only what was advertised:

- **When a feature is needed.** For an element whose refusal would cost
  more than a message (a screen diff refused ends the session, `screen.md`
  §5.9), for anything in a format with no critical marking (a transport
  frame kind, `transport.md` §4.2), and for a new value of a known
  element (a new attach mode, a new channel type), which a receiver of
  the element would refuse.
- **Where it is advertised.** In the handshake hello (`transport.md`
  §3.6): each side lists the features it understands, and the server's
  answer is the intersection, as for channel types (D15). Bootstrap and
  attach lines reserve the key `features` for the same purpose, a
  comma-separated list of names in ascending order; no line carries it
  yet, because nothing needs it yet.
- **Names.** A feature is a name in a registry kept here. In the text
  lines it is written as its name; in the binary hello as its registry
  code, one byte, to keep msg1 within 1200 bytes (D5).
- **No feature is registered.** Everything defined when these rules were
  adopted (2026-11-17) is part of protocol 1, and every receiver of
  protocol 1 knows it. The additions that prompted the rules need no
  feature: the screen's ROOT, CONTAINER and CWD are property ops that may
  be ignored (a mark on the tab, `screen.md` §5.4), and a ClientLine's
  `cmd`, `dir` and `type` are critical (`bootstrap.md` §6.2), so a server
  that does not know them refuses the line and the client says so.
  The screen's FARREMOTE (2026-11-27) is added in the same way, with no
  feature: a property op that may be ignored.

| code | name | what it allows | defined in |
|---|---|---|---|
| | | (none yet) | |

## 5. One protocol number per layer, and it names the envelope

Each layer has one protocol number, checked for equality with no range
(D8 V1). It names the **envelope only**: the framing every element sits
in, the core of a format, and the mandatory elements. Adding an element,
a value, an op or an event never changes it. Only a change of envelope
does, and that needs Dan's approval. There is no minor version: features
(§4) do that job.

| layer | where the number is | before 2026-11-17 | now |
|---|---|---|---|
| bootstrap lines: ClientLine, CredentialLine, ErrorLine, ProbeLine, ListLine (`bootstrap.md` §6, §4.7.2, §9.4) | the second word of each line (`bootstrap.Version`) | 2 (the ListLine said 1 of its own) | **1**, one number for all five |
| the attach socket: the greeting and messages `0x40`–`0x4F` (`server.md` §2.8) | the greeting's second word (`bootstrap.AttachProtocol`) | 2 | **1** |
| the connection: the hello and everything after it (data packets, frame kinds, SSP, the screen diff's core, userinput, channel frames) | the hello's first byte (`handshake.ProtocolVersion`) | 1 | **1** |
| the handshake messages msg1 and msg2 (`transport.md` §3.5, §3.7) | their version byte, tied to the protocol name (§3.1) | 1 | **1** (unchanged: it is the layout of two messages the protocol name fixes) |

`mosey --serve=protocol` prints the bootstrap number and the hello's:
`1 1` (`bootstrap.md` §4.7.2). A mismatch still fails with one line
naming both numbers ("dan-desktop's mosey speaks protocol 2; this mosey
speaks 1"), and now it can only mean a different envelope.

**What is not open.** The IPC between the spawner, proto and emu
(`server.md` §3.2, every type outside `0x40`–`0x4F`) is closed by design:
those roles are always the same executable, started from
`/proc/self/exe`, so there is never an older or newer peer to tolerate
(`server.md` §2.3). An unknown type or field there is refused as a
violation, as before, because the peer is the less trusted side (emu
parses the program's output) and ignoring anything would only widen what
it can reach. The transport's outer datagram types (`transport.md`
§2.1) are read before anything is authenticated and are dropped when
unknown, which is already ignoring them.

## 6. The text lines

Every line of `bootstrap.md` (ClientLine, CredentialLine, ErrorLine,
ProbeLine, ListLine) and the attach socket's greeting share one grammar:

```
line     = tag SP number *(SP field) LF
tag      = "MOSEY-" 1*12(%x41-5A)          ; MOSEY-CLIENT, MOSEY-CONNECT, ...
number   = "0" / (%x31-39 0*4DIGIT)        ; 0..99999, no leading zero
field    = [crit] key "=" value
crit     = "!"
key      = %x61-7A 0*15(%x61-7A / DIGIT / "-")   ; 1..16 bytes
value    = 1*(%x21-7E)                     ; printable ASCII, no space
SP       = %x20
LF       = %x0A
```

- **Frozen for ever**: the tag and the number, as the first two words of
  every line, so any build can say which number a line it cannot read
  is; and the ErrorLine's whole grammar and bound (`bootstrap.md` §6.4),
  so any build can read any other's refusal.
- **One space** between words; no leading or trailing space, no CR, no
  tab, no byte outside printable ASCII. A value runs to the next space
  or the LF; it may hold `=` and `!`, and its own grammar is its field's.
- **Keys in strictly ascending byte order**, comparing the key without
  its `!`. That refuses a duplicate, `!k=` beside `k=` included, and
  makes every set of fields one line.
- **No empty value.** An element that has nothing to say is left out:
  where the old grammar wrote `-`, the field is now absent.
- **At most `MaxFields` = 32 fields** a line [choice: twice the most any
  line defines], and each line's byte bound (its spec's `Max…Line`) holds
  whatever the fields are. Both are checked before any field is read.
- **Canonical.** A known field must be in exactly the form its marshaller
  writes, with its spec's critical marking. A parser accepts a line only
  if marshalling what it parsed gives back the line without its unknown
  fields: the round trip of known fields. Unknown fields without `!` are
  dropped; an unknown field with `!` refuses the line.
- **Booleans** are `yes`; a false flag is absent. Binary values are
  base64url without padding, decoded strictly (`bootstrap.md` §6.1).

## 7. What the fuzz targets check

Every parser of these formats has a fuzz target (CLAUDE.md), and each
checks, besides what it checked before:

1. **Unknown optional elements change nothing**: a message with an
   unknown element that may be ignored parses (or applies) to exactly
   what it does without it.
2. **Unknown critical elements are refused with nothing changed**: the
   same message with a critical one is refused, and the receiver's state
   is as it was.
3. **Known elements round-trip**: what is accepted re-encodes, without
   its unknown elements, to the same bytes, and parses back the same.
