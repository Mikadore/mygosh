#!/usr/bin/env python3
import base64
import struct
import sys
from pathlib import Path


class R:
    def __init__(self, b):
        self.b = b
        self.i = 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise ValueError("truncated")
        x = self.b[self.i : self.i + n]
        self.i += n
        return x

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def string(self):
        n = self.u32()
        return self.take(n)

    def mpint(self):
        return int.from_bytes(self.string(), "big", signed=False)

    def rest(self):
        return self.b[self.i :]


def clean_pem(path):
    lines = Path(path).read_text().splitlines()
    body = []
    inside = False
    for line in lines:
        if line == "-----BEGIN OPENSSH PRIVATE KEY-----":
            inside = True
            continue
        if line == "-----END OPENSSH PRIVATE KEY-----":
            break
        if inside:
            body.append(line.strip())
    return base64.b64decode("".join(body))


def hexs(b):
    return b.hex()


def b64(b):
    return base64.b64encode(b).decode()


def parse_public_blob(blob, indent="  "):
    r = R(blob)
    kt = r.string().decode()
    print(f"{indent}keytype: {kt}")

    if kt == "ssh-ed25519":
        pub = r.string()
        print(f"{indent}public: {hexs(pub)}")
        print(f"{indent}public_b64: {b64(pub)}")

    elif kt == "ssh-rsa":
        e = r.mpint()
        n = r.mpint()
        print(f"{indent}e: {e}")
        print(f"{indent}n: {n}")

    elif kt.startswith("ecdsa-sha2-"):
        curve = r.string().decode()
        q = r.string()
        print(f"{indent}curve: {curve}")
        print(f"{indent}Q: {hexs(q)}")

    else:
        print(f"{indent}raw_remaining: {hexs(r.rest())}")


def parse_private_key(r, indent="  "):
    kt = r.string().decode()
    print(f"{indent}keytype: {kt}")

    if kt == "ssh-ed25519":
        pub = r.string()
        priv = r.string()
        print(f"{indent}public: {hexs(pub)}")
        print(f"{indent}private_64: {hexs(priv)}")
        print(f"{indent}seed_32: {hexs(priv[:32])}")
        print(f"{indent}embedded_public_32: {hexs(priv[32:])}")

    elif kt == "ssh-rsa":
        n = r.mpint()
        e = r.mpint()
        d = r.mpint()
        iqmp = r.mpint()
        p = r.mpint()
        q = r.mpint()
        print(f"{indent}n: {n}")
        print(f"{indent}e: {e}")
        print(f"{indent}d: {d}")
        print(f"{indent}iqmp: {iqmp}")
        print(f"{indent}p: {p}")
        print(f"{indent}q: {q}")

    elif kt.startswith("ecdsa-sha2-"):
        curve = r.string().decode()
        q = r.string()
        d = r.mpint()
        print(f"{indent}curve: {curve}")
        print(f"{indent}Q: {hexs(q)}")
        print(f"{indent}d: {d}")

    else:
        print(f"{indent}unknown private key type; remaining parse may be wrong")

    comment = r.string().decode(errors="replace")
    print(f"{indent}comment: {comment!r}")


def strip_padding(b):
    # OpenSSH padding is 1,2,3,...; remove valid suffix only.
    for padlen in range(0, min(255, len(b)) + 1):
        if b[-padlen:] == bytes(range(1, padlen + 1)) if padlen else b"":
            return b[:-padlen], b[-padlen:]
    return b, b""


def main(path):
    data = clean_pem(path)

    magic = b"openssh-key-v1\x00"
    if not data.startswith(magic):
        raise ValueError("not openssh-key-v1")

    print(f"magic: {magic[:-1].decode()!r}")

    r = R(data[len(magic) :])
    cipher = r.string().decode()
    kdf = r.string().decode()
    kdfopts = r.string()
    nkeys = r.u32()

    print(f"ciphername: {cipher!r}")
    print(f"kdfname: {kdf!r}")
    print(f"kdfoptions: {hexs(kdfopts)}")
    print(f"nkeys: {nkeys}")

    publics = []
    for i in range(nkeys):
        blob = r.string()
        publics.append(blob)
        print(f"\npublic_keys[{i}]:")
        print(f"  blob_hex: {hexs(blob)}")
        print(f"  blob_b64: {b64(blob)}")
        parse_public_blob(blob, "  ")

    enc = r.string()
    if cipher != "none" or kdf != "none":
        raise ValueError("encrypted keys not supported by this dumper")

    pr = R(enc)
    c1 = pr.u32()
    c2 = pr.u32()
    print(f"\ncheckint1: {c1:#x}")
    print(f"checkint2: {c2:#x}")
    print(f"checkints_match: {c1 == c2}")

    for i in range(nkeys):
        print(f"\nprivate_keys[{i}]:")
        parse_private_key(pr, "  ")

    padding = pr.rest()
    print(f"\npadding_len: {len(padding)}")
    print(f"padding_hex: {hexs(padding)}")
    print(f"padding_valid: {padding == bytes(range(1, len(padding) + 1))}")


if __name__ == "__main__":
    main(sys.argv[1])
