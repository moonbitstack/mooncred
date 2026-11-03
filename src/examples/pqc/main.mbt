// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A certificate under an ML-DSA-65 key (RFC 9881): the key from a seed, the certificate written
/// for it, and the PEM that `openssl x509` reads back.
///
///     moon run src/examples/mldsa
///
/// The seed is the one thing to replace before using this for anything: a key that anyone can
/// derive from a constant is a key anyone can sign with.
#coverage.skip
fn main raise {
  let seed = @base16.decode(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let key : @x509.PrivateKey = MlDsa(
    @mldsa.PrivateKey::from_seed(kind=D65, seed),
  )
  let der = @x509.self_signed(
    key~,
    cn="pqc.example",
    serial=b"\x01",
    not_before=1767225600L,
    not_after=2082758400L,
    exts={
      ..@x509.Exts::empty(),
      san: [Dns("pqc.example")],
      key_usage: Some({ bytes: b"\x80", unused: 7, }),
    },
  )
  let cert = @x509.parse(der)
  println("subject      \{cert.subject.cn().unwrap_or("?")}")
  println("algorithm    \{cert.alg}")
  println("key          1952 octets, ML-DSA-65")
  println("self-signed  \{cert.signed_by(cert.spki)}")
  println("names host   \{cert.matches("pqc.example")}")
  println(@x509.pem_wrap(der))
}
