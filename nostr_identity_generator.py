#!/usr/bin/env python3
"""
Nostr Identity Generator – zero external libraries (UX-friendly)

What’s new (UX)
- Clean, looped main menu with clear actions
- Safe-by-default display: private key hidden unless you explicitly reveal
- One-key shortcuts (1/2/3/4/R/Q) and Enter for defaults
- Friendly confirmations, error messages, and warnings
- Optional JSON export with smart default filename
- **No clipboard dependency** (we removed the copy-to-clipboard feature)

Usage
  python nostr_identity_generator.py                 # interactive
  python nostr_identity_generator.py --new           # quick: print and exit
  python nostr_identity_generator.py --import KEY    # KEY = 64-hex | nsec1... | npub1...
  python nostr_identity_generator.py --new --out keys.json

This script uses **only Python’s standard library**.

Docs: NIP-01 (secp256k1/x-only pubkey), NIP-06 (BIP39 derivation — not implemented here),
NIP-11 (relay info), **NIP-19 (bech32 encodings)**.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from secrets import token_bytes
from typing import Iterable, List, Optional, Tuple

# =========================
# Styling (ANSI colors)
# =========================
class S:
    R = "\033[31m"  # red
    G = "\033[32m"  # green
    Y = "\033[33m"  # yellow
    B = "\033[34m"  # blue
    M = "\033[35m"  # magenta
    C = "\033[36m"  # cyan
    D = "\033[2m"   # dim
    X = "\033[0m"   # reset


def color(s: str, c: str) -> str:
    if sys.stdout.isatty():
        return f"{c}{s}{S.X}"
    return s


# =========================
# secp256k1 math (pure Python)
# =========================
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A  = 0
B  = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G  = (Gx, Gy)

Point = Optional[Tuple[int, int]]


def _mod_inv(a: int, m: int) -> int:
    return pow(a % m, -1, m)


def _is_on_curve(Pt: Point) -> bool:
    if Pt is None:
        return True
    x, y = Pt
    return (y * y - (x * x * x + B)) % P == 0


def _point_add(P1: Point, P2: Point) -> Point:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        s = (3 * x1 * x1 + A) * _mod_inv(2 * y1, P) % P
    else:
        s = (y2 - y1) * _mod_inv(x2 - x1, P) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k: int, Pt: Point) -> Point:
    if k % N == 0 or Pt is None:
        return None
    if k < 0:
        return _scalar_mult(-k, (Pt[0], (-Pt[1]) % P))
    result: Point = None
    addend: Point = Pt
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def privkey_to_pubkey_point(sk: int) -> Point:
    Pt = _scalar_mult(sk, G)
    assert Pt is not None and _is_on_curve(Pt)
    return Pt


def privkey_to_xonly_pubkey(sk: int) -> bytes:
    x, y = privkey_to_pubkey_point(sk)
    return x.to_bytes(32, 'big')


def privkey_to_compressed_pubkey(sk: int) -> bytes:
    x, y = privkey_to_pubkey_point(sk)
    prefix = 0x02 if (y % 2 == 0) else 0x03
    return bytes([prefix]) + x.to_bytes(32, 'big')


# =========================
# Bech32 (BIP-173) – NIP-19
# =========================
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_MAP = {c: i for i, c in enumerate(CHARSET)}


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _polymod(values: Iterable[int]) -> int:
    GEN = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def _create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_encode(hrp: str, data: List[int]) -> str:
    combined = data + _create_checksum(hrp, data)
    return hrp + '1' + ''.join(CHARSET[d] for d in combined)


def _bech32_decode(bech: str) -> Tuple[str, List[int]]:
    bech = bech.strip()
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        raise ValueError("Invalid bech32 chars")
    if bech.lower() != bech and bech.upper() != bech:
        raise ValueError("Mixed case bech32 not allowed")
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech):  # at least 1 char HRP and 6 char checksum
        raise ValueError("Invalid bech32 position")
    hrp = bech[:pos]
    data_part = bech[pos + 1:]
    try:
        data = [CHARSET_MAP[c] for c in data_part]
    except KeyError:
        raise ValueError("Invalid bech32 data chars")
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("Invalid bech32 checksum")
    return hrp, data[:-6]  # strip checksum


def _convertbits(data: Iterable[int], frombits: int, tobits: int, pad: bool = True) -> List[int]:
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for b in data:
        if b < 0 or (b >> frombits):
            raise ValueError("Invalid byte for convertbits")
        acc = ((acc << frombits) | b) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding in convertbits")
    return ret


def hex_to_nip19(hrp: str, hexstr: str) -> str:
    raw = bytes.fromhex(hexstr)
    data = _convertbits(raw, 8, 5, pad=True)
    return _bech32_encode(hrp, data)


def nip19_to_hex(expected_hrp: str, bech: str) -> str:
    hrp, data5 = _bech32_decode(bech)
    if hrp != expected_hrp:
        raise ValueError(f"Expected HRP '{expected_hrp}', got '{hrp}'")
    raw_bytes = bytes(_convertbits(data5, 5, 8, pad=False))
    return raw_bytes.hex()


# =========================
# Nostr identity utilities
# =========================
@dataclass
class NostrIdentity:
    privkey_hex: str
    pubkey_hex: str  # x-only (32 bytes)
    nsec: str
    npub: str
    compressed_pubkey_hex: str


def generate_privkey() -> int:
    while True:
        sk = int.from_bytes(token_bytes(32), 'big')
        if 1 <= sk < N:
            return sk


def identity_from_priv_hex(priv_hex: str) -> NostrIdentity:
    priv_hex = priv_hex.lower().strip()
    if priv_hex.startswith('nsec1'):
        raise ValueError("Provide a 64-char hex for this action, or use --import with nsec.")
    if len(priv_hex) != 64 or any(c not in '0123456789abcdef' for c in priv_hex):
        raise ValueError("Private key must be 64 hex chars.")
    sk = int(priv_hex, 16)
    if not (1 <= sk < N):
        raise ValueError("Private key out of range.")
    pub_x = privkey_to_xonly_pubkey(sk)
    pub_hex = pub_x.hex()
    cpk = privkey_to_compressed_pubkey(sk).hex()
    return NostrIdentity(
        privkey_hex=priv_hex,
        pubkey_hex=pub_hex,
        nsec=hex_to_nip19('nsec', priv_hex),
        npub=hex_to_nip19('npub', pub_hex),
        compressed_pubkey_hex=cpk,
    )


def identity_from_nsec(nsec: str) -> NostrIdentity:
    nsec = nsec.strip().lower()
    if not nsec.startswith('nsec1'):
        raise ValueError("Not an nsec string.")
    priv_hex = nip19_to_hex('nsec', nsec)
    return identity_from_priv_hex(priv_hex)


def new_identity() -> NostrIdentity:
    sk = generate_privkey()
    priv_hex = f"{sk:064x}"
    return identity_from_priv_hex(priv_hex)


def save_identity_json(identity: NostrIdentity, path: str) -> None:
    payload = {
        "hex": {
            "privkey": identity.privkey_hex,
            "pubkey": identity.pubkey_hex,
            "compressed_pubkey": identity.compressed_pubkey_hex,
        },
        "nip19": {"nsec": identity.nsec, "npub": identity.npub},
        "created_at": int(time.time()),
    }
    data = json.dumps(payload, indent=2)
    # POSIX: 0600
    if os.name != 'nt':
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(data)
    else:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(data)


# =========================
# UX Helpers
# =========================

def hr():
    print(color("\n" + "─" * 60 + "\n", S.D))


def prompt(msg: str, default: Optional[str] = None) -> str:
    if default is not None:
        msg = f"{msg} {S.D}[{default}]{S.X} " if sys.stdout.isatty() else f"{msg} [{default}] "
    try:
        val = input(msg)
    except EOFError:
        return default or ''
    return (val or '').strip() or (default or '')


def yesno(msg: str, default: bool = False) -> bool:
    d = 'Y/n' if default else 'y/N'
    resp = prompt(f"{msg} ({d})", '').lower()
    if not resp:
        return default
    return resp in ('y', 'yes')


def banner():
    hr()
    print(color("Nostr Identity Generator", S.C))
    print(color("zero external libraries · safe-by-default · Made by DrShift", S.D))
    hr()


def print_identity(identity: NostrIdentity, reveal_priv: bool = False) -> None:
    print(color("Your Nostr Identity", S.B))
    print("npub (public):     ", color(identity.npub, S.G))
    print("pubkey (hex, x-only): ", identity.pubkey_hex)
    print("pubkey (compressed): ", identity.compressed_pubkey_hex)
    if reveal_priv:
        print(color("nsec (PRIVATE):     ", S.Y) + color(identity.nsec, S.Y))
        print(color("privkey (hex, PRIVATE): ", S.Y) + color(identity.privkey_hex, S.Y))
    else:
        print(color("nsec (PRIVATE):     [hidden]", S.D))
        print(color("privkey (hex):      [hidden]", S.D))
    print(color("\n⚠ Keep your nsec/private key SECRET. Whoever has it controls your identity.", S.R))


def export_flow(identity: NostrIdentity):
    if yesno("Save keys to a JSON file?", True):
        default_name = f"nostr_identity_{int(time.time())}.json"
        path = prompt("File path:", default_name)
        try:
            save_identity_json(identity, path)
            print(color(f"Saved: {path}", S.G))
        except Exception as e:
            print(color(f"Failed to save: {e}", S.R))


def view_identity(identity: NostrIdentity):
    reveal = yesno("Reveal PRIVATE values (nsec/privkey) on screen?", False)
    print()
    print_identity(identity, reveal_priv=reveal)
    while True:
        print("\nActions:  (E)xport  (R)eturn")
        act = prompt("Pick action:", "R").lower()
        if act in ("r", "return"):
            break
        if act in ("e", "export"):
            export_flow(identity)


# =========================
# Convert / Validate (NIP-19)
# =========================

def is_hex64(s: str) -> bool:
    s = s.strip().lower()
    return len(s) == 64 and all(c in '0123456789abcdef' for c in s)


def convert_validate_menu():
    while True:
        hr()
        print(color("Convert / Validate (no clipboard, pure stdlib)", S.B))
        print("1) npub  → pubkey hex")
        print("2) nsec  → privkey hex")
        print("3) priv 64-hex → npub / nsec / pubkey (compressed)")
        print("4) pubkey hex (x-only) → npub")
        print("B) Back")
        choice = prompt("Select:", "B").lower()
        try:
            if choice == '1':
                npub = prompt("Paste npub…:")
                pub_hex = nip19_to_hex('npub', npub)
                print(color("pubkey hex:", S.G), pub_hex)
            elif choice == '2':
                nsec = prompt("Paste nsec…:")
                priv_hex = nip19_to_hex('nsec', nsec)
                print(color("privkey hex:", S.G), priv_hex)
            elif choice == '3':
                priv_hex = prompt("Paste 64-hex private key:")
                if not is_hex64(priv_hex):
                    raise ValueError("Needs 64 hex chars")
                ident = identity_from_priv_hex(priv_hex)
                print(color("npub:", S.G), ident.npub)
                print(color("nsec:", S.G), ident.nsec)
                print(color("pubkey (hex, x-only):", S.G), ident.pubkey_hex)
                print(color("pubkey (compressed):", S.G), ident.compressed_pubkey_hex)
            elif choice == '4':
                pub_hex = prompt("Paste pubkey hex (x-only, 64 hex chars):")
                pub_hex = pub_hex.strip().lower()
                if not is_hex64(pub_hex):
                    raise ValueError("Needs 64 hex chars")
                print(color("npub:", S.G), hex_to_nip19('npub', pub_hex))
            elif choice in ('b', 'back'):
                break
        except Exception as e:
            print(color(f"Error: {e}", S.R))


# =========================
# Readme / tips
# =========================

def safety_tips():
    hr()
    print(color("Safety tips", S.B))
    print("• Never paste your nsec/private key into websites or chats.")
    print("• Prefer hardware wallets/signers for serious use (see NIP-46).")
    print("• Back up your JSON export (0600 perms will be used on POSIX).")
    print("• x-only pubkeys (NIP-01) are 32 bytes; npub/nsec are NIP-19 bech32.")
    input(color("\nPress Enter to return…", S.D))


# =========================
# Interactive Menu
# =========================

def main_menu():
    while True:
        banner()
        print("1) Generate NEW identity")
        print("2) Import from private key (64-hex)")
        print("3) Import from nsec (bech32)")
        print("4) Convert/Validate formats")
        print("R) Read me / safety tips")
        print("Q) Quit")
        choice = prompt("Select:", "1").lower()

        try:
            if choice == '1':
                ident = new_identity()
                view_identity(ident)
            elif choice == '2':
                priv = prompt("Paste 64-hex private key:")
                ident = identity_from_priv_hex(priv)
                view_identity(ident)
            elif choice == '3':
                nsec = prompt("Paste nsec… string:")
                ident = identity_from_nsec(nsec)
                view_identity(ident)
            elif choice == '4':
                convert_validate_menu()
            elif choice == 'r':
                safety_tips()
            elif choice == 'q':
                print("Bye!")
                break
        except KeyboardInterrupt:
            print("\nCancelled.")
        except Exception as e:
            print(color(f"Error: {e}", S.R))
        time.sleep(0.05)


# =========================
# CLI
# =========================

def parse_args():
    ap = argparse.ArgumentParser(description="Nostr Identity Generator (no external libs)")
    ap.add_argument('--new', action='store_true', help='Generate a new identity and print')
    ap.add_argument('--import', dest='import_key', help='Import a key: 64-hex | nsec1...')
    ap.add_argument('--out', help='Save JSON to this path')
    return ap.parse_args()


def main():
    args = parse_args()
    if args.new or args.import_key:
        if args.new:
            ident = new_identity()
        else:
            key = args.import_key.strip()
            if key.startswith('nsec1'):
                ident = identity_from_nsec(key)
            elif is_hex64(key):
                ident = identity_from_priv_hex(key)
            else:
                raise SystemExit("--import expects 64-hex priv or nsec1…")
        # print non-interactive summary
        print_identity(ident, reveal_priv=True)
        if args.out:
            try:
                save_identity_json(ident, args.out)
                print(color(f"Saved JSON → {args.out}", S.G))
            except Exception as e:
                print(color(f"Failed to save JSON: {e}", S.R))
        return
    # Interactive
    main_menu()


if __name__ == '__main__':
    main()
