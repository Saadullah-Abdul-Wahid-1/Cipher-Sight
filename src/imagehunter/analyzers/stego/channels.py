"""Channel views and bit-plane rendering for inspection (no interpretation here)."""

from __future__ import annotations

import io


def to_pixel_array(data: bytes):
    """Decode with Pillow and return (array (H,W,C) uint8, channel names, mode). Raises on decode failure."""
    import numpy as np
    from PIL import Image

    with Image.open(io.BytesIO(data)) as img:
        if img.mode in ("LA", "PA", "RGBA") or "transparency" in img.info:
            img = img.convert("RGBA")
        elif img.mode == "L":
            pass
        else:
            img = img.convert("RGB")
        arr = np.array(img, dtype=np.uint8)
        mode = img.mode
    if arr.ndim == 2:
        arr = arr[:, :, None]
        names = ["L"]
    else:
        names = ["R", "G", "B", "A"][: arr.shape[2]]
    return arr, names, mode


def alpha_stats(arr, names: list[str]) -> dict:
    """Summary of the alpha channel: a common place for hidden data in RGBA images."""
    import numpy as np
    if "A" not in names:
        return {"present": False}
    a = arr[:, :, names.index("A")]
    values, counts = np.unique(a, return_counts=True)
    return {
        "present": True,
        "min": int(a.min()),
        "max": int(a.max()),
        "distinct_values": int(values.size),
        "fully_opaque": bool((a == 255).all()),
    }


def render_bitplane(arr, channel: str, bit: int, names: list[str]):
    """Return a Pillow 'L' image of one bit plane (0 or 255 per pixel), same size as the source."""
    import numpy as np
    from PIL import Image

    plane = ((arr[:, :, names.index(channel)] >> bit) & 1) * 255
    return Image.fromarray(plane.astype(np.uint8), mode="L")
