// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// PBES2 (RFC 7518 §4.8): the key-encryption key is derived from a password with PBKDF2, and
// what is then wrapped is the content key. The salt is the algorithm's own name, a zero, and
// the salt the sender chose, so one password under two algorithms derives two keys.

///|
/// The fewest iterations RFC 7518 §4.8.1.2 allows.
let pbes2_floor : Int32 = 1000

///|
/// Derive the key-encryption key from a password.
fn pbes2_kek(
  alg : Alg,
  password : BytesView,
  salt : BytesView,
  count : Int32,
) -> Bytes raise Refused {
  if count < pbes2_floor {
    raise Malformed(
      "a PBES2 iteration count of \{count}, below the \{pbes2_floor} RFC 7518 §4.8.1.2 sets",
    )
  }
  let mixed = Buffer()
  mixed.write_bytes(@utf8.encode(alg.name())[:])
  mixed.write_byte(0x00)
  mixed.write_bytesview(salt)
  let hash : () -> &@spec.Hash = match alg {
    Pbes2Hs384A192Kw => fn() { @sha2.Hasher::new(kind=Sha384) }
    Pbes2Hs512A256Kw => fn() { @sha2.Hasher::new(kind=Sha512) }
    _ => fn() { @sha2.Hasher::new() }
  }
  @pbkdf2.key(
    password,
    mixed.to_bytes()[:],
    hash,
    rounds=count,
    len=match alg {
      Pbes2Hs256A128Kw => 16
      Pbes2Hs384A192Kw => 24
      _ => 32
    },
  )
}
