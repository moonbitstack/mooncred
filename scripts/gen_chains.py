"""Write x509/chains_test.mbt: the certificate chains the path-validation tests run on.

Every chain is issued fresh by Python's `cryptography` (OpenSSL), so the validator is checked
against certificates it did not write. Rerun after changing a scenario; the keys are new each
time, the expectations are not.
"""

import datetime as dt
import ipaddress
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = pathlib.Path(__file__).resolve().parent.parent / "x509" / "chains_test.mbt"
START = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
END = dt.datetime(2040, 1, 1, tzinfo=dt.timezone.utc)


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def build(cn, key, issuer=None, *, ca=False, path_len=None, ku=None, eku=None, san=None,
          nc=None, critical_unknown=False, start=START, end=END, digest: hashes.HashAlgorithm = hashes.SHA256(),
          pss=False, ski=True, aki=True):
    issuer_cert, issuer_key = issuer if issuer else (None, key)
    b = (x509.CertificateBuilder()
         .subject_name(name(cn))
         .issuer_name(issuer_cert.subject if issuer_cert else name(cn))
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(start)
         .not_valid_after(end))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=path_len), critical=True)
    if ku == "ca":
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                            critical=True)
    elif ku == "sign":
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                            critical=True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san:
        names = []
        for s in san:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                names.append(x509.DNSName(s))
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if nc:
        permitted, excluded = nc
        b = b.add_extension(x509.NameConstraints(permitted_subtrees=permitted or None,
                                                 excluded_subtrees=excluded or None), critical=True)
    if critical_unknown:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"),
                            critical=True)
    if ski:
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if aki and issuer_cert is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                            critical=False)
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        cert = b.sign(issuer_key, None)
    elif pss:
        cert = b.sign(issuer_key, digest,
                      rsa_padding=padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.DIGEST_LENGTH))
    else:
        cert = b.sign(issuer_key, digest)
    return cert, key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def main():
    server = [ExtendedKeyUsageOID.SERVER_AUTH]
    certs = {}

    root = build("rsa root", rsa_key(), ca=True, ku="ca")
    inter = build("rsa inter", rsa_key(), root, ca=True, ku="ca")
    certs["rsa_root"], certs["rsa_inter"] = root[0], inter[0]
    certs["leaf"] = build("leaf", ec.generate_private_key(ec.SECP256R1()), inter, ku="sign", eku=server,
                          san=["a.example", "*.w.example", "127.0.0.1", "::1"], digest=hashes.SHA384())[0]

    p384 = build("p384 root", ec.generate_private_key(ec.SECP384R1()), ca=True, ku="ca", digest=hashes.SHA384())
    certs["p384_root"] = p384[0]
    certs["p384_leaf"] = build("p384 leaf", ec.generate_private_key(ec.SECP256R1()), p384, eku=server,
                               san=["b.example"], digest=hashes.SHA384())[0]

    ed = build("ed root", ed25519.Ed25519PrivateKey.generate(), ca=True, ku="ca")
    certs["ed_root"] = ed[0]
    certs["ed_leaf"] = build("ed leaf", ed25519.Ed25519PrivateKey.generate(), ed, san=["c.example"])[0]

    pss = build("pss root", rsa_key(), ca=True, ku="ca", pss=True)
    certs["pss_root"] = pss[0]
    certs["pss_leaf"] = build("pss leaf", rsa_key(), pss, san=["d.example"], pss=True)[0]

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    certs["expired"] = build("expired", leaf_key, inter, san=["a.example"],
                             end=dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc))[0]
    early = build("early inter", rsa_key(), root, ca=True, ku="ca",
                  start=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
    certs["early_inter"] = early[0]
    certs["early_leaf"] = build("early leaf", leaf_key, early, san=["a.example"])[0]
    certs["client"] = build("client", leaf_key, inter, eku=[ExtendedKeyUsageOID.CLIENT_AUTH], san=["a.example"])[0]
    noca = build("noca inter", rsa_key(), root)
    certs["noca_inter"] = noca[0]
    certs["noca_leaf"] = build("noca leaf", leaf_key, noca, san=["a.example"])[0]
    nosign = build("nosign inter", rsa_key(), root, ca=True, ku="sign")
    certs["nosign_inter"] = nosign[0]
    certs["nosign_leaf"] = build("nosign leaf", leaf_key, nosign, san=["a.example"])[0]
    pl0 = build("pl0 inter", rsa_key(), root, ca=True, path_len=0, ku="ca")
    below = build("below inter", rsa_key(), pl0, ca=True, ku="ca")
    certs["pl0_inter"], certs["below_inter"] = pl0[0], below[0]
    certs["pl0_leaf"] = build("pl0 leaf", leaf_key, below, san=["a.example"])[0]
    certs["critical"] = build("critical", leaf_key, inter, san=["a.example"], critical_unknown=True)[0]

    nc = ([x509.DNSName("allowed.example")], [x509.IPAddress(ipaddress.ip_network("10.0.0.0/8"))])
    nci = build("nc inter", rsa_key(), root, ca=True, ku="ca", nc=nc)
    certs["nc_inter"] = nci[0]
    certs["nc_ok"] = build("nc ok", leaf_key, nci, san=["x.allowed.example"])[0]
    certs["nc_dns"] = build("nc dns", leaf_key, nci, san=["x.other.example"])[0]
    certs["nc_ip"] = build("nc ip", leaf_key, nci, san=["x.allowed.example", "10.1.2.3"])[0]
    ncr = build("nc root", rsa_key(), ca=True, ku="ca", nc=nc)
    certs["nc_root"] = ncr[0]
    certs["nc_root_leaf"] = build("nc root leaf", leaf_key, ncr, san=["x.other.example"])[0]

    real = build("decoyed", rsa_key(), root, ca=True, ku="ca", ski=False)
    certs["decoyed_inter"] = real[0]
    certs["decoyed_leaf"] = build("decoyed leaf", leaf_key, real, san=["a.example"], aki=False)[0]
    for i in range(5):
        certs[f"decoy{i}"] = build("decoyed", rsa_key(), root, ca=True, ku="ca", ski=False)[0]

    out = ["// Generated by scripts/gen_chains.py; rerun it rather than editing.", ""]
    for k, c in certs.items():
        out.append("///|")
        out.append(f"let {k} : String =")
        out.extend("  #|" + line for line in pem(c).strip().split("\n"))
        out.append("")
    OUT.write_text("\n".join(out), encoding="utf-8", newline="\n")
    print(f"wrote {len(certs)} certificates to {OUT}")


if __name__ == "__main__":
    main()
