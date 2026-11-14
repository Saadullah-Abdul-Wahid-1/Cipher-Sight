"""LSB / bit-plane extraction over lossless pixel data.

An experiment is a combination of:
  channel     R, G, B, A (or L for grayscale)
  bit plane   0 = least significant bit, up to 7
  traversal   "row"        pixels read left-to-right, top-to-bottom
              "column"     pixels read top-to-bottom, left-to-right
              "serpentine" rows read alternately left-to-right and right-to-left
              "diagonal"   anti-diagonals, from the top-left corner outward
  bit order   how 8 extracted bits form one byte: "LSB-first" or "MSB-first"
  xor key     every byte is XORed with each key 0..255 (single-byte XOR)

Each experiment yields a byte stream. A stream is accepted only if it contains PREFIX{...}, where PREFIX
is in settings.flag_prefixes (default THM, CTF, FLAG, flag, HTB, picoCTF). Nothing else is reported, which keeps noise low.
The stream covers the whole image up to `max_bytes`. Unknown-prefix flag-like
leads are searched separately and reported as low-confidence evidence, never as
confirmed flags.

Repeating-key XOR (key length 2 to lsb_repeating_key_max) is searched with a known-prefix
(crib) method: see repeating_key_hits(). Keys longer than that, and payloads that are compressed
or encrypted, are not covered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TRAVERSALS = ("row", "column", "serpentine", "diagonal")
BIT_ORDERS = ("LSB-first", "MSB-first")
BIT_SHIFTS = tuple(range(8))   # payloads may start at any bit position in the traversal stream


def flag_pattern(prefixes) -> "re.Pattern[bytes]":
    """Matches PREFIX{body} where PREFIX is one of the configured names and body is printable
    text up to the first '}'. Prefixes make random bytes almost never match."""
    alternation = "|".join(re.escape(p) for p in sorted(prefixes, key=len, reverse=True))
    return re.compile(rb"(?:" + alternation.encode("ascii") + rb")\{[\x20-\x7e]{1,100}?\}")


@dataclass(frozen=True)
class LsbHit:
    text: str
    channel: str
    bit: int
    traversal: str
    bit_order: str
    xor_key: int
    byte_offset: int        # position within the decoded byte stream
    pixel_index: int        # traversal index of the first bit of the match
    first_pixel: tuple[int, int]
    kind: str = "flag"          # "flag" = configured prefix; "lead" = readable unknown-prefix text
    key: bytes = b""            # repeating XOR key (length >= 2); empty for single-byte or no XOR
    bit_shift: int = 0          # leading bits skipped before packing (payload not byte-aligned to the stream start)


def channel_names(n_channels: int) -> list[str]:
    return {1: ["L"], 3: ["R", "G", "B"], 4: ["R", "G", "B", "A"]}[n_channels]


def traversal_prefix(H: int, W: int, traversal: str, count: int):
    """Row-major flat indices of the first `count` pixels in traversal order (int64 array)."""
    import numpy as np
    count = int(min(max(count, 0), H * W))
    if count == 0:
        return np.zeros(0, dtype=np.int64)
    if traversal == "row":
        return np.arange(count, dtype=np.int64)
    if traversal == "column":                      # x outer, y inner
        cols = -(-count // H)
        xs = np.repeat(np.arange(cols), H)
        ys = np.tile(np.arange(H), cols)
        return (ys * W + xs)[:count].astype(np.int64)
    if traversal == "serpentine":                  # odd rows run right-to-left
        rows = -(-count // W)
        ys = np.repeat(np.arange(rows), W)
        xs = np.tile(np.arange(W), rows)
        xs = np.where(ys % 2 == 1, W - 1 - xs, xs)
        return (ys * W + xs)[:count].astype(np.int64)
    if traversal == "diagonal":                    # anti-diagonals s = x + y, y increasing
        parts, total, s_ = [], 0, 0
        while total < count and s_ <= H + W - 2:
            y0, y1 = max(0, s_ - (W - 1)), min(H - 1, s_)
            ys = np.arange(y0, y1 + 1)
            parts.append(ys * W + (s_ - ys))
            total += ys.size
            s_ += 1
        return np.concatenate(parts)[:count].astype(np.int64)
    raise ValueError(f"unknown traversal: {traversal}")


def pixel_xy(index: int, width: int, height: int, traversal: str) -> tuple[int, int]:
    flat = int(traversal_prefix(height, width, traversal, index + 1)[index])
    y, x = divmod(flat, width)
    return x, y


def extract_bits(arr, channel: int, bit: int, traversal: str, count: int):
    """First `count` bits of one bit plane, in the requested traversal order. arr is (H, W, C) uint8."""
    import numpy as np
    H, W, _ = arr.shape
    plane = ((arr[:, :, channel] >> bit) & 1).reshape(-1)
    return plane[traversal_prefix(H, W, traversal, count)].astype(np.uint8)


def pack_bits(bits, bit_order: str):
    import numpy as np
    usable = (len(bits) // 8) * 8
    grouped = bits[:usable].reshape(-1, 8).astype(np.uint16)
    if bit_order == "LSB-first":
        weights = (1 << np.arange(8)).astype(np.uint16)
    else:
        weights = (128 >> np.arange(8)).astype(np.uint16)
    return (grouped * weights).sum(axis=1).astype(np.uint8)


def scan_pixels(arr, channels: list[str], max_bytes: int, prefixes) -> list[LsbHit]:
    """Run every experiment over an (H, W, C) uint8 array and return flag-format hits."""
    import numpy as np

    pattern = flag_pattern(prefixes)
    needles = [p.encode("ascii") for p in prefixes]
    H, W, _ = arr.shape
    max_bits = min(max_bytes * 8, H * W)
    keys = np.arange(256, dtype=np.uint8)[:, None]
    hits: list[LsbHit] = []

    for ci, cname in enumerate(channels):
        for bit in range(8):
            for traversal in TRAVERSALS:
                bits = extract_bits(arr, ci, bit, traversal, max_bits)
                for order in BIT_ORDERS:
                    stream = pack_bits(bits, order)
                    if stream.size < 4:
                        continue
                    candidates = keys ^ stream[None, :]          # (256, n): every XOR key at once
                    for key in range(256):
                        raw = candidates[key].tobytes()
                        if not any(n in raw for n in needles):   # fast reject: no prefix at all
                            continue
                        for m in pattern.finditer(raw):
                            pixel_index = m.start() * 8
                            hits.append(LsbHit(
                                text=m.group().decode("latin-1"),
                                channel=cname,
                                bit=bit,
                                traversal=traversal,
                                bit_order=order,
                                xor_key=key,
                                byte_offset=m.start(),
                                pixel_index=pixel_index,
                                first_pixel=pixel_xy(pixel_index, W, H, traversal),
                            ))
    return hits


# ---------------------------------------------------------------------------
# Multi-channel streams and unknown-prefix leads (Phase 4 extension)
# ---------------------------------------------------------------------------

LEAD_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,15}\{[\x20-\x7e]{3,80}?\}")


def channel_sequences(names: list[str], max_channels: int) -> list[tuple[int, ...]]:
    """Ordered channel tuples of length 1..max_channels, e.g. (0,), (1,), (0,1), (1,0), ...
    Order matters: (0,1) reads channel 0 then channel 1 for each pixel."""
    from itertools import permutations
    out: list[tuple[int, ...]] = []
    for n in range(1, max(1, min(max_channels, len(names))) + 1):
        out.extend(permutations(range(len(names)), n))
    return out


def extract_interleaved(arr, seq: tuple[int, ...], bit: int, traversal: str, count: int):
    """Bit stream that takes, for each pixel in traversal order, one bit from each channel in `seq`."""
    import numpy as np
    H, W, _ = arr.shape
    k = len(seq)
    planes = np.stack([((arr[:, :, c] >> bit) & 1).reshape(-1) for c in seq], axis=-1)   # (H*W, k)
    pixels = traversal_prefix(H, W, traversal, -(-count // k))
    return planes[pixels].reshape(-1)[:count].astype(np.uint8)


_COMMON_PAIRS = frozenset(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve "
    "co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur".split())


def looks_periodic(text: str) -> bool:
    """True when a long stretch repeats with a short period, such as 'TNkTNkTNk'.

    Smooth image bit planes produce these, and they are not flags. Test: for period p, the longest
    run of positions where text[i] == text[i+p] must be at least 8 and cover half the text."""
    n = len(text)
    if n < 8:
        return False
    for period in range(1, 9):
        if 2 * period > n:
            break
        run = best = 0
        for i in range(n - period):
            run = run + 1 if text[i] == text[i + period] else 0
            best = max(best, run)
        if best >= 8 and best + period >= n / 2:
            return True
    return False


def readable_body(body: bytes) -> bool:
    """Reject obvious noise while allowing natural language and CTF-style bodies.

    Natural-language bodies pass an English letter-pair heuristic. Compact flag
    bodies can instead pass when they contain enough distinct letters plus
    digits/underscores (for example ``t3st_fl4g_lsb_42``). These remain weak
    leads because their prefixes are not configured by the analyst.
    """
    import re as _re
    text = body.decode("latin-1")
    if len(text) < 3 or len(text) > 80:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{8,}", text):   # bare hex is the most common source of false leads
        return False
    if looks_periodic(text):
        return False
    if sum(1 for c in text if c.isalnum() or c == "_") / len(text) < 0.7:
        return False
    runs = _re.findall(r"[A-Za-z]+", text)
    if _re.search(r"([A-Za-z])\1\1", text):          # 'lll', 'yyy': noise from repeated bytes
        return False
    long_runs = [r for r in runs if len(r) >= 3]
    if not long_runs or len({c.lower() for c in max(long_runs, key=len)}) < 3:
        return False
    pairs = common = 0
    for r in runs:
        r = r.lower()
        for i in range(len(r) - 1):
            pairs += 1
            if r[i:i + 2] in _COMMON_PAIRS:
                common += 1

    # CTF flag bodies commonly use leetspeak and short underscore-separated
    # fragments (for example: t3st_fl4g_lsb_42). Requiring English bigram
    # frequency alone rejects these legitimate flag bodies. Keep the existing
    # natural-language test, but also accept a constrained flag-like form.
    natural_language = pairs >= 4 and common / pairs >= 0.4
    letters = [c for c in text if c.isalpha()]
    flag_like = (
        len(letters) >= 6
        and (any(c.isdigit() for c in text) or "_" in text)
        and len(runs) >= 2
        and len(set(c.lower() for c in letters)) >= 4
    )
    return natural_language or flag_like


def single_byte_keys(stream, needles) -> set[int]:
    """Every single-byte XOR key k for which some needle occurs in (stream ^ k).

    Equivalent to trying all 256 keys, but vectorised: if needle N occurs at offset j with key k,
    then k = stream[j] ^ N[0] and stream[j+i] ^ stream[j] == N[i] ^ N[0] for all i. Only offsets
    satisfying that are visited, so the 256 x n candidate matrix is never built.
    """
    import numpy as np
    keys: set[int] = set()
    n = stream.size
    for needle in needles:
        m = len(needle)
        if m == 0 or m > n:
            continue
        span = n - m + 1
        base = stream[:span]
        ok = np.ones(span, dtype=bool)
        for i in range(1, m):
            ok &= (stream[i:i + span] ^ base) == (needle[i] ^ needle[0])
        for j in np.nonzero(ok)[0].tolist():
            keys.add(int(stream[j]) ^ needle[0])
    return keys


def _plausible_crib_body(body: bytes) -> bool:
    """Stricter than readable_body for crib matches: the prefix is guaranteed, so only the body counts."""
    if readable_body(body):
        return True
    import re as _re
    text = body.decode("latin-1")
    if looks_periodic(text):
        return False
    return (len(text) >= 6 and _re.fullmatch(r"[A-Za-z0-9_!@#$%&*+\-]+", text) is not None
            and sum(1 for c in text if c.isalpha()) >= 3 and any(c.isdigit() or c == "_" for c in text)
            and len(set(text)) >= 5)


def repeating_key_hits(stream, prefixes, pattern, max_key_len: int, max_candidates: int = 64):
    """Crib-based search for repeating-key XOR, key length 2..max_key_len.

    For a configured prefix P (plus '{'), every offset j is a candidate flag start. Under key length L,
    stream[j+i] ^ P[i] is the key byte for phase (j+i) % L. Random data almost never makes those
    derived bytes agree at every repeated phase, so only consistent offsets are tried. Each surviving key
    decrypts the whole stream and the flag pattern is then checked with the regex.

    Returns a list of (text, key_bytes, byte_offset). Deduplicated by (text, key).
    """
    import numpy as np
    n = stream.size
    seen, out = set(), []
    for prefix in prefixes:
        crib = np.frombuffer(prefix.encode("ascii") + b"{", dtype=np.uint8)
        m = crib.size
        for L in range(2, max_key_len + 1):
            if m < L + 1:                     # need the whole key covered and at least one repeated phase
                continue
            span = n - m + 1
            if span <= 0:
                continue
            # Same phase mod L => the derived key byte must agree. Check the first pair on the whole
            # stream, then the remaining pairs only on the few survivors.
            pairs = [(i, i2) for i in range(m) for i2 in range(i + L, m, L)]
            i1, j1 = pairs[0]
            cand = np.nonzero((stream[i1:i1 + span] ^ crib[i1]) == (stream[j1:j1 + span] ^ crib[j1]))[0]
            for a, b in pairs[1:]:
                if cand.size == 0:
                    break
                cand = cand[(stream[cand + a] ^ crib[a]) == (stream[cand + b] ^ crib[b])]
            positions = cand[:max_candidates]
            window = 16
            for j in positions.tolist():
                table = np.zeros(L, dtype=np.uint8)
                for i in range(m):
                    table[(j + i) % L] = stream[j + i] ^ crib[i]
                if np.all(table == table[0]):          # constant key: the single-byte path already covers it
                    continue
                # Cheap check before decrypting the whole stream: the bytes right after the crib must be
                # printable under this key. Most consistent offsets fail here.
                end = min(n, j + m + window)
                seg = (stream[j + m:end] ^ table[np.arange(j + m, end) % L]).tolist()
                head = seg[:seg.index(0x7D)] if 0x7D in seg else seg    # stop at the closing brace
                if any(not (0x20 <= c <= 0x7E) for c in head):
                    continue
                decrypted = (stream ^ table[np.arange(n) % L]).tobytes()
                for mt in pattern.finditer(decrypted):
                    # The crib makes the prefix decrypt correctly by construction, so the prefix alone
                    # says nothing. The body must look like a real flag body.
                    body = mt.group().split(b"{", 1)[1].rstrip(b"}")
                    if not _plausible_crib_body(body):
                        continue
                    key = bytes(table.tolist())
                    tag = (mt.group(), key)
                    if tag not in seen:
                        seen.add(tag)
                        out.append((mt.group().decode("latin-1"), key, mt.start()))
    return out


def scan_sequences(arr, names: list[str], max_bytes: int, prefixes, max_channels: int = 1,
                   leads: bool = False, repeating_key_max: int = 0, bit_shifts=BIT_SHIFTS):
    """Search every channel sequence, bit plane, traversal, bit order, bit shift, and XOR key.

    Single-byte keys are found from crib offsets (single_byte_keys); repeating keys of length 2 to
    repeating_key_max use repeating_key_hits(). Returns (flag_hits, lead_hits). flag_hits match configured
    prefixes. lead_hits are readable text with a prefix that is NOT configured, and are computed only at
    bit shift 0, because they are low-confidence leads and the full XOR matrix is expensive.
    """
    import numpy as np

    pattern = flag_pattern(prefixes)
    needles = [p.encode("ascii") for p in prefixes]
    configured = set(prefixes)
    H, W, _ = arr.shape
    keys = np.arange(256, dtype=np.uint8)[:, None]
    flags: list[LsbHit] = []
    lead_hits: list[LsbHit] = []

    for seq in channel_sequences(names, max_channels):
        label = "+".join(names[i] for i in seq)
        k = len(seq)
        max_bits = min(max_bytes * 8, H * W * k)
        for bit in range(8):
            for traversal in TRAVERSALS:
                bits = extract_interleaved(arr, seq, bit, traversal, max_bits + max(bit_shifts, default=0))
                for shift in bit_shifts:
                    shifted = bits[shift:shift + max_bits]
                    for order in BIT_ORDERS:
                        stream = pack_bits(shifted, order)
                        if stream.size < 4:
                            continue
                        for key in sorted(single_byte_keys(stream, needles)):
                            raw = (stream ^ np.uint8(key)).tobytes()
                            for m in pattern.finditer(raw):
                                flags.append(_hit(m, m.group().decode("latin-1"), label, bit, traversal,
                                                  order, key, k, H, W, "flag", shift=shift))
                        if repeating_key_max >= 2:
                            for text, key, pos in repeating_key_hits(stream, prefixes, pattern, repeating_key_max):
                                flags.append(_hit_at(pos, text, label, bit, traversal, order, key[0], k, H, W,
                                                     "flag", shift=shift, key_bytes=key))
                        if leads and shift == 0:
                            candidates = keys ^ stream[None, :]
                            _leads_for_stream(candidates, labels_for(label), bit, traversal, order,
                                              configured, lead_hits, H, W, k)
    return flags, lead_hits


def labels_for(label: str) -> str:
    return label


def _leads_for_stream(candidates, label, bit, traversal, order, configured, lead_hits, H, W, k):
    """Find readable unknown-prefix text in all 256 XOR outputs of one stream.

    Vectorised pre-filter: a lead needs '{' with two word characters before it and printable text after
    it. Only the survivors are checked with the regular expression, so most bytes never reach Python.
    """
    import numpy as np
    n = candidates.shape[1]
    kk, jj = np.nonzero(candidates == ord("{"))
    if kk.size == 0:
        return
    word = np.zeros(256, dtype=bool)
    for c in range(256):
        word[c] = chr(c).isalnum() and c < 128 or c == ord("_")
    printable = (candidates >= 0x20) & (candidates <= 0x7E)
    keep = (jj >= 2) & (jj + 3 < n)
    kk, jj = kk[keep], jj[keep]
    ok = (word[candidates[kk, jj - 1]] & word[candidates[kk, jj - 2]]
          & printable[kk, jj + 1] & printable[kk, jj + 2] & printable[kk, jj + 3])
    kk, jj = kk[ok], jj[ok]
    raw_cache: dict[int, bytes] = {}
    for key, j in zip(kk.tolist(), jj.tolist()):
        raw = raw_cache.get(key)
        if raw is None:
            raw = raw_cache[key] = candidates[key].tobytes()
        lo, hi = max(0, j - 16), min(len(raw), j + 90)
        for m in LEAD_RE.finditer(raw, lo, hi):
            brace = m.group().index(b"{") + m.start()
            if brace != j:
                continue
            name = m.group().split(b"{", 1)[0].decode("latin-1")
            if name in configured:
                continue
            body = m.group().split(b"{", 1)[1].rstrip(b"}")
            if readable_body(body):
                lead_hits.append(_hit(m, m.group().decode("latin-1"), label, bit, traversal, order,
                                      key, k, H, W, "lead"))


def _hit(m, text, label, bit, traversal, order, key, k, H, W, kind, shift=0) -> LsbHit:
    return _hit_at(m.start(), text, label, bit, traversal, order, key, k, H, W, kind, shift=shift)


def _hit_at(pos, text, label, bit, traversal, order, key, k, H, W, kind, shift=0, key_bytes=b"") -> LsbHit:
    bit_index = pos * 8 + shift
    pixel_index = bit_index // k
    return LsbHit(text=text, channel=label, bit=bit, traversal=traversal, bit_order=order,
                  xor_key=key, byte_offset=pos, pixel_index=pixel_index,
                  first_pixel=pixel_xy(pixel_index, W, H, traversal), kind=kind, bit_shift=shift,
                  key=key_bytes)
