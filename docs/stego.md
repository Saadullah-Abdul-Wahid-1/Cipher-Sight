# LSB and bit-plane analysis (Phase 4)

## What the analyzer does
For lossless images (PNG, BMP), it tries every combination of:

| Dimension | Values |
|---|---|
| Channel | R, G, B (and A if present; L for grayscale) |
| Bit plane | 0 (LSB) to 7 |
| Pixel order | row (left-to-right, top-to-bottom) or column (top-to-bottom, left-to-right) |
| Bits within a byte | LSB-first or MSB-first |
| XOR key | every byte XORed with 0x00 to 0xFF |

For a 640x480 RGB image that is 3 × 8 × 2 × 2 × 256 = 24,576 decoded streams, all
covering the whole image. The scan takes about 2 seconds for 640x480.

## Channel streams (v0.9.0)
Setting `lsb_max_channels` (default 1) controls how many channels are read together:

| value | channel streams | cost on a 640x480 RGB image |
|---|---|---|
| 1 | R, G, B (single channel) | about 2 seconds |
| 2 | adds R+G, G+R, ... (interleaved: one bit per channel, per pixel) | about 15 seconds with leads |
| 3 | adds R+G+B and all 6 orders | about 50 seconds with leads |

Interleaved stream order: for each pixel in traversal order, one bit from each channel in the sequence.
Order matters: `R+G` and `G+R` are different streams.

## Unknown-prefix leads (v0.9.0)
Setting `lsb_unknown_prefix_leads` (default false). When true, readable text such as `RHL{stone_w0rd_xor}`
whose prefix is not in `flag_prefixes` is reported as `lsb_unknown_prefix_lead`, confidence Low.
A lead is not a candidate. Add its prefix to `flag_prefixes` to report it as a candidate.

Readability test for leads: the text in braces (3 to 80 characters) must be at least 70% letters, digits
or underscores; a run of 3 or more letters must exist; no letter may repeat three times in a row; the longest
run needs 3 distinct letters; and at least 40% of its letter pairs must be common English pairs
(`th`, `he`, `in`, `er`, `st`, `or` ...). Leetspeak digits break runs, so `stone_w0rd_xor` passes.
This filter is heuristic: readable phrases with uncommon letter pairs (for example `quaint_moon`) can be missed.

## Acceptance rule
A stream is reported only if it contains `PREFIX{body}`, where PREFIX is one of
`settings.flag_prefixes` (default: THM, CTF, FLAG, flag, HTB, picoCTF) and body is
printable text up to the first `}`. Anything else is ignored, which keeps random
data from producing findings.

Every finding is `High`. The label means the text matches a flag format. It does not
mean the text is the real answer. A decoy with the same format is reported too, and
you decide which one is correct.

## Evidence in each finding
- `text`: the matched text.
- `experiments`: every configuration that produced this text (channel, bit, order, bit order, XOR key).
- `first_pixel`: the (x, y) of the first matched bit in the traversal that found it.
- `byte_offset`: position of the match in the decoded stream.

## Assumptions and limits
- Only lossless formats. JPEG is skipped, because quantisation destroys LSB data.
- Single-byte XOR keys only. Multi-byte keys, other transforms (Base64, ROT13, Caesar), and
  compressed or encrypted payloads are not detected here. Flag Hunter (Phase 6) and the
  external-tool adapters (Phase 5) cover those.
- The stream is limited to `stego_max_bytes` (default 65536 bytes). Larger payloads are cut off.
- Images with more than `max_pixels` (default 20,000,000) are skipped with a warning.
- Only one bit-plane and traversal layout per flag. Layouts that mix channels, skip pixels, or
  use a different start offset are not covered unless the start is found by the regex (it is,
  for byte-aligned starts).
- A flag split across two channels or two bit planes is not reassembled.

## Helpers
- `channels.render_bitplane(arr, channel, bit, names)` returns a black-and-white image of one bit plane.
  Use it to inspect the plane visually.
- `channels.alpha_stats(arr, names)` summarises the alpha channel.

## Known-answer tests
`tests/unit/test_lsb.py` embeds payloads with `embed_lsb` in `tests/fixtures/generate.py`, then
checks that the analyzer recovers the exact configuration. Covered cases: row/LSB-first, column/MSB-first
with XOR, bit plane 3, alpha channel, grayscale, clean noise (no findings), JPEG skip, oversize skip.

`make_signal_hunt_like()` rebuilds the structure of the challenge image from its answer key, on a noise
base. The test expects both layers with exact first pixels (37,0) and (0,0).

Mutation check: ignoring the column order makes 2 tests fail. Ignoring the bit order makes 3 tests fail.

v0.9.0 tests (`tests/unit/test_stego_channels.py`): channel-sequence counts and order, interleaved 2- and 3-channel
round trips, single-channel behaviour unchanged, leads on and off, configured prefixes never become leads, noise
produces no leads, readability cases, and settings validation.
