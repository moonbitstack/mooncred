"""Write src/x509/keys_test.mbt: private keys in every form the reader takes, and broken ones.

The well-formed keys are written by Python's `cryptography` (OpenSSL); the broken ones are
assembled here from the same keys, one defect each. Rerun after changing a case.
"""

import base64
import pathlib

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

OUT = pathlib.Path(__file__).resolve().parent.parent / "src" / "x509" / "keys_test.mbt"

OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_P256 = "1.2.840.10045.3.1.7"
OID_P384 = "1.3.132.0.34"


def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(size)]) + size
    return bytes([tag]) + head + body


def seq(*items):
    return tlv(0x30, b"".join(items))


def integer(v):
    body = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return tlv(0x02, body)


def octets(b):
    return tlv(0x04, b)


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)


def pem(label, der):
    body = base64.b64encode(der).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "\n".join([f"-----BEGIN {label}-----", *lines, f"-----END {label}-----"])


def private_pem(key, fmt, enc=None):
    return key.private_bytes(ser.Encoding.PEM, fmt, enc or ser.NoEncryption()).decode().strip()


def spki(key):
    return key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo).hex()


def point(key):
    return key.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)


def sec1(scalar, curve_oid, pub):
    items = [integer(1), octets(scalar)]
    if curve_oid:
        items.append(tlv(0xA0, oid(curve_oid)))
    if pub:
        items.append(tlv(0xA1, tlv(0x03, b"\x00" + pub)))
    return seq(*items)


def pkcs8_ec(curve_oid, inner):
    return seq(integer(0), seq(oid(OID_EC), oid(curve_oid)), octets(inner))


def main():
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p256 = ec.generate_private_key(ec.SECP256R1())
    p384 = ec.generate_private_key(ec.SECP384R1())
    p521 = ec.generate_private_key(ec.SECP521R1())
    k256 = ec.generate_private_key(ec.SECP256K1())
    ed = ed25519.Ed25519PrivateKey.generate()
    xk = x25519.X25519PrivateKey.generate()
    # A scalar below 2^248 has a zero leading octet, which old OpenSSL dropped.
    short = ec.derive_private_key(0x5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A, ec.SECP256R1())

    pkcs8, trad = ser.PrivateFormat.PKCS8, ser.PrivateFormat.TraditionalOpenSSL
    ed_seed = ed.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    ed_pub = ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    rn = rk.private_numbers()
    other_prime = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers().p
    p256_scalar = p256.private_numbers().private_value.to_bytes(32, "big")

    values = {
        "rsa_pkcs8": private_pem(rk, pkcs8),
        "rsa_pkcs1": private_pem(rk, trad),
        "rsa_spki": spki(rk),
        "p256_pkcs8": private_pem(p256, pkcs8),
        # `openssl ecparam -genkey` writes the curve in its own block ahead of the key.
        "p256_sec1": pem("EC PARAMETERS", oid(OID_P256)) + "\n" + private_pem(p256, trad),
        "p256_spki": spki(p256),
        "p384_pkcs8": private_pem(p384, pkcs8),
        "p384_spki": spki(p384),
        "p521_pkcs8": private_pem(p521, pkcs8),
        "p521_spki": spki(p521),
        "k256_pkcs8": private_pem(k256, pkcs8),
        "k256_spki": spki(k256),
        "ed_pkcs8": private_pem(ed, pkcs8),
        "ed_spki": spki(ed),
        "ed_pkcs8_v2": pem("PRIVATE KEY", seq(
            integer(1), seq(oid(OID_ED25519)), octets(octets(ed_seed)), tlv(0x81, b"\x00" + ed_pub))),
        "short_sec1": pem("EC PRIVATE KEY", sec1(
            short.private_numbers().private_value.to_bytes(31, "big"), OID_P256, point(short))),
        "short_spki": spki(short),
        "padded_sec1": pem("EC PRIVATE KEY", sec1(b"\x00" + p256_scalar, OID_P256, None)),
        "bare_pkcs8": pem("PRIVATE KEY", pkcs8_ec(OID_P256, sec1(p256_scalar, None, None))),
        "bare_sec1": pem("EC PRIVATE KEY", sec1(p256_scalar, None, None)),
        "foreign_point": pem("EC PRIVATE KEY", sec1(p256_scalar, OID_P256, point(short))),
        "curve_clash": pem("PRIVATE KEY", pkcs8_ec(OID_P256, sec1(p256_scalar, OID_P384, None))),
        "ed_foreign": pem("PRIVATE KEY", seq(
            integer(1), seq(oid(OID_ED25519)), octets(octets(ed_seed)), tlv(0x81, b"\x00" + bytes(32)))),
        "rsa_bad_primes": pem("RSA PRIVATE KEY", seq(
            integer(0), integer(rn.public_numbers.n), integer(rn.public_numbers.e), integer(rn.d),
            integer(other_prime), integer(rn.q), integer(rn.dmp1), integer(rn.dmq1), integer(rn.iqmp))),
        "x25519_pkcs8": private_pem(xk, pkcs8),
        "encrypted_pkcs8": private_pem(p256, pkcs8, ser.BestAvailableEncryption(b"secret")),
        "encrypted_legacy": private_pem(p256, trad, ser.BestAvailableEncryption(b"secret")),
    }
    out = ["// Generated by scripts/gen_keys.py; rerun it rather than editing.", ""]
    for k, v in values.items():
        out.append("///|")
        if "\n" in v:
            out.append(f"let {k} : String =")
            out.extend("  #|" + line for line in v.split("\n"))
        else:
            out.append(f'let {k} : String = "{v}"')
        out.append("")
    OUT.write_text("\n".join(out), encoding="utf-8", newline="\n")
    print(f"wrote {len(values)} values to {OUT}")


if __name__ == "__main__":
    main()
