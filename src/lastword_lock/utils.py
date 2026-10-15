"""
Helper utilities: networking, formatting, and terminal QR code display.
"""

import socket
import io
from typing import List


def get_local_ips() -> List[str]:
    """
    Find non-loopback local network IP addresses.
    """
    ips = []
    # Technique 1: Connect UDP socket to public DNS to find default outgoing route
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        default_ip = s.getsockname()[0]
        s.close()
        if default_ip and not default_ip.startswith("127."):
            ips.append(default_ip)
    except Exception:
        pass

    # Technique 2: Hostname resolution
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass

    if not ips:
        ips.append("127.0.0.1")

    return ips


def render_qr_ascii(data: str) -> str:
    """
    Generate an ASCII / Unicode block QR code string for terminal printing.
    """
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        out = io.StringIO()
        qr.print_ascii(out=out, invert=True)
        text = out.getvalue()
        # Verify it can be encoded in current stdout
        import sys
        enc = sys.stdout.encoding or "utf-8"
        text.encode(enc)
        return text
    except Exception:
        return ""


def format_hashrate(hashes_per_second: float) -> str:
    """
    Format hashrate in H/s, KH/s, MH/s, GH/s.
    """
    if hashes_per_second < 1e3:
        return f"{hashes_per_second:.1f} H/s"
    elif hashes_per_second < 1e6:
        return f"{hashes_per_second / 1e3:.2f} KH/s"
    elif hashes_per_second < 1e9:
        return f"{hashes_per_second / 1e6:.2f} MH/s"
    else:
        return f"{hashes_per_second / 1e9:.2f} GH/s"


def format_seconds(seconds: float) -> str:
    """
    Format time duration into a human-readable string.
    """
    if seconds < 0 or seconds > 1e9:
        return "unknown"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = int(minutes // 60)
    mins = int(minutes % 60)
    if hours < 24:
        return f"{hours}h {mins}m"
    days = int(hours // 24)
    hrs = int(hours % 24)
    return f"{days}d {hrs}h"


def format_bytes(num_bytes: int) -> str:
    """
    Format byte size into B, KB, MB, GB.
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"
