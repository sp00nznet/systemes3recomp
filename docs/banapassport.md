# The banapassport, as far as it has been read

Everything here was measured against Mario Kart Arcade GP DX v1.00.32. The
addresses are that build's; the shape should hold across the Namco line, which
is why this is in the shared runtime's docs rather than the game's.

## The reader

An **NXP PN53x** NFC controller on a serial port - COM4 on this tree, chosen by
name at `0x005BD830`. `card.c` answers it. The card it presents is an ordinary
**MIFARE Classic 1K**, polled with `InListPassiveTarget` BrTy `0x00` (106 kbps
type A) and answered with SAK `0x08`.

Sector 0's key A is **`60 90 D0 06 32 F5`**, which the game sends in the clear
and which also sits in `.rdata` at `0x0081DC6C`.

The game reads exactly two blocks - 0 and 1 - and then releases the card.

### What a cabinet does, which is not what a test does

An empty reader is polled continuously; a card that is already in the field is
read once during the reader's power-on test and then never polled again. In one
run: **7349 polls with no card, 1 with a card glued on**. So the resting state
is empty and a card is an event - `card.c` models it as a tap, and
`ES3_CARD_ALWAYS` exists only for scripted runs and warns that it misleads.

## The card

The game does **not** ask its server whether a card is good. It judges the bytes
itself: across every run the only All.Net call made is `/sys/servlet/PowerOn`,
never anything under `/amid/`. So an unrecognised card never reaches the network
at all.

### The signature

`L_007ACE40` takes six bytes off the card and does, at `0x007AD037`:

```
push 5
push eax              ; the six bytes
push 0x81dc64         ; "NBGIC"
call 0x7cb6ae         ; memcmp(..., 5)
test eax, eax
jne  0x7ad0a3         ; mismatch -> rejected
```

and then requires the sixth byte to be one of `'0'`, `'3'`, `'6'` or `'7'`:

```
mov al, [esi+0x125]
cmp al, 0x30 / 0x33 / 0x36 / 0x37
```

So a card begins `NBGIC` plus a generation digit.

### The generation table, and the cipher behind it

`L_007AE4A0` then walks a table of **eight entries at `0x0081DCB0`, stride
`0x88`**, matching a dword and two bytes from the card. The entries are
`NBGIC0` through `NBGIC7`, and each is:

```
+00  8 bytes   "NBGICn\0\0"
+08  128 bytes key material
```

128 bytes per generation, and the algorithm that uses it is **Blowfish**.

That is not a guess. The per-generation context is `0x1048` bytes, which is
exactly Blowfish's 18-dword P-array plus four 256-entry S-boxes
(72 + 4096 = 4168). `L_007AE1E0` is textbook Blowfish: four S-box lookups at
`+0x000`, `+0x400`, `+0x800` and `+0xC00` folded as
`((S0[a] + S1[b]) ^ S2[c]) + S3[d]`, sixteen rounds, and a P-array walked
**backwards** from `+0x1044` - so that function is the decrypt. `L_007AE270`
starts at the P-array base and runs forward: the key schedule, expanding the
`.rdata` key into the context in `.data` at `0x009462A8`, stride `0x1048`,
indexed by generation.

### So a card can be minted, not only dumped

Blowfish is symmetric. The key is in the binary, the expanded context is in
the game's own memory, and the same key that decrypts a card encrypts one. A
card body can therefore be built rather than copied from real hardware:

  1. choose the identity - the plaintext is a dword, a word and a byte, which
     is what `L_007ACDC0` reads back out at `+0x128`, `+0x12C` and `+0x12E`
  2. fold the XOR check byte the way `0x007AE576` checks it
  3. Blowfish-encrypt the eight-byte block with the chosen generation's key
  4. write `NBGIC` + the generation digit and the field around it, with the
     `0x0200` version word `0x007AE532` insists on

Generations `6` and `7` are the ones to mint: there are three validators, at
`0x007ACE40`, `0x007AD183` and `0x007AD3E7`, accepting `0 3 6 7`, `2 5 6 7`
and `1 4 6 7` respectively, so only 6 and 7 satisfy all three.

What is **not** yet pinned down is the exact byte layout inside the sixteen
byte field. The offsets in `L_007AE4A0` are read through a stack copy whose
base moves with several pushes, and guessing them from the listing is how
mistakes get made. The reliable way is to dump the expanded context from
`0x009462A8` out of the running game and work against that.

`L_007ACDC0` is the second gate: it parses 16 further bytes at `+0x13F` and
returns `-400` (`0xFFFFFE70`) when they do not parse. The signature path's own
rejection at `0x007AD0A3` returns `-400` or `-256` depending on a flag, and sets
the reader's state word at `+0x110` to `0x102`.

## The profile is not on the card

A banapassport carries an identity and nothing else. The name, the coins and
the unlocks live on the game's server, behind the `/amid/` family that
`allnet.c` currently answers with `{"status":0}`.

This was worth establishing because it is easy to assume otherwise: the two
"100% Unlocked BanaPassport Save Profile" archives that prompted this work are
byte-identical to each other, contain no card data at all, and hold a .NET GUI
- *MKDX Unlocked Profile v2.1* - that pushes a profile into a server over HTTP
at `player/getData`, `judgement/getData` and `amid/getAmidInfo_bf`, by default
on `127.0.0.1:49200`.

So the profile work is `allnet.c`'s, and it is gated behind a card the game
will accept. `ES3_TRACE_AMID` keeps the request bodies - base64 of a zlib
stream - for when that day comes; they decode to plain key=value:

```
game_id=SBZB&ver=0.01&serial=ABGN0020001&ip=192.0.2.1&firm_ver=20007&...
```

## Map

| address | what |
| --- | --- |
| `0x007AA3C0` | reader transport open; objects at `0x00943548`, stride `0x590`, 8 of them |
| `0x007ABE40` | write one PN53x frame |
| `0x007B0090` | generic "write the whole buffer", loops on the `WriteFile` pointer in `0x0081D0D0` |
| `0x007ACE40` | the card validator - signature, generation digit |
| `0x007ACDC0` | second gate, parses `+0x13F`, `-400` on failure |
| `0x007AE4A0` | generation table lookup at `0x0081DCB0`, then decrypt and check |
| `0x007AE1E0` | Blowfish decrypt, 16 rounds, P-array walked backwards |
| `0x007AE270` | Blowfish key schedule; contexts at `0x009462A8`, stride `0x1048` |
| `0x007AD183` / `0x007AD3E7` | the other two validators, accepting `2 5 6 7` and `1 4 6 7` |
| `0x0081DC64` | `"NBGIC"` |
| `0x0081DC6C` | MIFARE sector 0 key A |

A note on finding these: `ES3_TRACE_CARD` prints who drives the reader, and it
first printed `007B00D7` - inside the generic buffer writer, true and useless.
One stack frame is not the answer when the call is indirect. The rest came from
taking that address into the lifted source and walking the call graph up.
