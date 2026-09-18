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

### The generation table, and why this stops here

`L_007AE4A0` then walks a table of **eight entries at `0x0081DCB0`, stride
`0x88`**, matching a dword and two bytes from the card. The entries are
`NBGIC0` through `NBGIC7`, and each is:

```
+00  8 bytes   "NBGICn\0\0"
+08  128 bytes key material
```

128 bytes is RSA-1024. Read big-endian the blob is even, so it is not a modulus
that way round; read little-endian it is odd and 1023 bits, which is the shape
of one. Either way it is a per-generation key, one for each of the eight card
generations, and the card's body is protected with it.

**That is the wall.** A card body cannot be fabricated without the matching
secret, so a working virtual banapassport needs a **dump of a real card** - a
1 KB MIFARE image - rather than more code. That is data this project does not
have and cannot derive.

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
| `0x007AE4A0` | generation table lookup at `0x0081DCB0` |
| `0x0081DC64` | `"NBGIC"` |
| `0x0081DC6C` | MIFARE sector 0 key A |

A note on finding these: `ES3_TRACE_CARD` prints who drives the reader, and it
first printed `007B00D7` - inside the generic buffer writer, true and useless.
One stack frame is not the answer when the call is indirect. The rest came from
taking that address into the lifted source and walking the call graph up.
