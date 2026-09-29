"""Perceptual image hashing for favicon correlation.

Why this exists
---------------
`favicon_hash` is a byte-exact digest of the icon file. That is the right thing
to store for chain of custody -- it proves two responses were the same file --
but it cannot answer the question the index actually needs: *is this the same
image?* An operator who re-saves an ICO, re-encodes it as PNG, or resizes it
produces a different digest for an identical picture, and every byte-exact
correlator silently misses it.

So both are kept: the exact digest for provenance, and a perceptual hash for
matching. They answer different questions and neither substitutes for the other.

Implementation
--------------
A difference hash (dHash) on a greyscale reduction: compare each pixel with
its right-hand neighbour and record which is brighter. Chosen over a DCT hash
because it needs no matrix maths, so it runs in pure Python without numpy --
which is not importable in the bundled runtime, where the tests must be able to
execute from a USB stick.

The grid is a parameter. Small images (favicons, avatars) use 9x8 for 64 bits;
a full-page screenshot is dominated by layout and needs more rows, so it uses
17x16 for 256 bits. `hamming` refuses to compare hashes of different lengths,
since XOR-ing a 64-bit and a 256-bit value would report a meaningless distance
that could still land inside a threshold.
"""
import io

# Distance at which two dHashes are considered the same image. Conservative by
# design: this feeds an attribution claim about a person, so a false match is
# worse than a miss. 8/64 is well inside the range usually cited for dHash.
DEFAULT_THRESHOLD = 8

try:
    from PIL import Image
except Exception:  # pragma: no cover - Pillow absent; exact hashing still works
    Image = None

# Guards against decompression bombs and absurd canvas sizes in hostile favicons.
MAX_BYTES = 2 * 1024 * 1024
MAX_PIXELS = 4096 * 4096


def _iter_grayscale(img, grid=(9, 8)):
    """Greyscale, as a flat list of intensities in row-major order.

    Uses tobytes() rather than getdata(), which Pillow 14 deprecates. Mode "L"
    is one byte per pixel, so the raw buffer is exactly the values wanted.
    """
    if img.mode != "L":
        img = img.convert("L")
    return list(img.resize((grid[0], grid[1]), Image.LANCZOS).tobytes())


# A favicon is 16x16, so an 8x8 grid of neighbour comparisons is already finer
# than the source. A full-page screenshot carries far more detail and is
# dominated by page furniture, so it uses a larger grid: more bits, and enough
# rows that a single shifted element does not flip the whole hash.
AVATAR_GRID = (9, 8)
SCREENSHOT_GRID = (17, 16)


def dhash(image_bytes, grid=AVATAR_GRID):
    """Difference hash as hex, or "" if not computable.

    grid is (w, h); the hash is (w-1)*h bits, so AVATAR_GRID gives 64 bits and
    SCREENSHOT_GRID gives 256. Thresholds are grid-specific -- see `near`.

    Returns "" rather than raising for anything undecodable: these images are
    attacker-controlled and a corrupt one must never break a crawl.
    """
    if not image_bytes or Image is None:
        return ""
    if len(image_bytes) > MAX_BYTES:
        return ""
    w, h = grid
    if w < 2 or h < 1:
        return ""
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            if img.width * img.height > MAX_PIXELS:
                return ""
            px = _iter_grayscale(img, (w, h))
    except Exception:
        return ""
    bits = 0
    for row in range(h):
        base = row * w
        for col in range(w - 1):
            bits = (bits << 1) | (1 if px[base + col] > px[base + col + 1] else 0)
    return f"{bits:0{(w - 1) * h // 4}x}"


def avatar_dhash(image_bytes):
    return dhash(image_bytes, AVATAR_GRID)


def screenshot_dhash(image_bytes):
    return dhash(image_bytes, SCREENSHOT_GRID)


def hamming(a, b):
    """Bit distance between two hex hashes. Non-hex or mismatched input -> -1.

    Mismatched *lengths* also return -1: comparing a 64-bit favicon hash against a
    256-bit screenshot hash would otherwise XOR two integers of different width
    and report a meaningless distance that could fall inside a threshold.
    """
    if not a or not b or len(a) != len(b):
        return -1
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except (TypeError, ValueError):
        return -1


def near(a, b, threshold=DEFAULT_THRESHOLD):
    d = hamming(a, b)
    return d >= 0 and d <= threshold
