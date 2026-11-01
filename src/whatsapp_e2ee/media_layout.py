"""Progressive-media scan lengths to encrypted chunk boundaries.

The input is the encoder's positive scan-length array, not offsets discovered by
searching for JPEG marker bytes. This implements the observed Pyp/Oyg layout;
JPEG encoding and choosing scan partitions remain the caller's responsibility.
"""

from whatsapp_e2ee.media import chunks


def scan_chunk_sizes(scan_lengths):
    lengths = tuple(scan_lengths)
    if len(lengths) < 2 or any(type(n) is not int or not 0 < n <= 0x7FFFFFFF for n in lengths):
        raise ValueError("At least two positive int32 scan lengths required")
    plaintext_length = sum(lengths)
    total = (plaintext_length // 16 + 1) * 16 + 10
    cumulative = boundary = previous_boundary = 0
    result = []
    for index, length in enumerate(lengths):
        cumulative += length
        if index == len(lengths) - 1:
            if cumulative > boundary:
                tail = total - boundary
            else:
                if not result:
                    raise ValueError("Empty scan layout")
                result.pop()
                tail = total - previous_boundary
            if not 0 < tail <= 0x7FFFFFFF:
                raise ValueError("Encrypted scan chunk exceeds int32")
            result.append(tail)
        elif cumulative > boundary:
            size = ((cumulative - boundary + 15) // 16) * 16
            if size > 0x7FFFFFFF:
                raise ValueError("Aligned scan chunk exceeds int32")
            result.append(size)
            previous_boundary, boundary = boundary, boundary + size
    chunks(total, result)
    return tuple(result)


def scan_prefix_length(scan_lengths):
    """Optional native four-scan plaintext prefix: sum of the first three scans."""
    lengths = tuple(scan_lengths)
    scan_chunk_sizes(lengths)
    return sum(lengths[:3]) if len(lengths) == 4 else None


__all__ = ["scan_chunk_sizes", "scan_prefix_length"]
