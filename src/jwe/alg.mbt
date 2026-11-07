// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The key-management half of RFC 7518: how a content-encryption key reaches one recipient.
// Every one of them ends in the same place — a key of the content algorithm's size, and a
// header that says what was done — and they differ only in what they ask the caller for.

///|
/// A key-management algorithm (RFC 7518 §4).
///
/// The list is deliberately complete rather than curated: a recipient that cannot name
/// `RSA1_5` cannot read a message that uses it. Every one of them is accepted without being
/// asked; [`Policy`] is where a deployment refuses the two it would rather not answer for.
#derive(Eq, Debug)
pub(all) enum Alg {
  /// The shared key is the content-encryption key: nothing is wrapped.
  Dir
  A128Kw
  A192Kw
  A256Kw
  /// AES-GCM over the content key: the tag and nonce travel in the header.
  A128GcmKw
  A192GcmKw
  A256GcmKw
  /// RSAES-PKCS1-v1_5 (RFC 8017 §7.2): no integrity of its own, and a padding oracle in its
  /// construction. Accepted by default for the traffic that already uses it; [`strict`] refuses
  /// it.
  Rsa1_5
  /// RSAES-OAEP with SHA-1: the same padding, under a hash that is no longer a barrier.
  RsaOaep
  RsaOaep256
  /// ECDH-ES: the content key is derived, so there is exactly one recipient.
  EcdhEs
  EcdhEsA128Kw
  EcdhEsA192Kw
  EcdhEsA256Kw
  Pbes2Hs256A128Kw
  Pbes2Hs384A192Kw
  Pbes2Hs512A256Kw
}

///|
pub extend Alg with Eq::{equal, not_equal}

///|
pub extend Alg with Debug::{to_repr}

///|
/// The name this algorithm goes by in a header.
pub fn Alg::name(self : Alg) -> String {
  match self {
    Dir => "dir"
    A128Kw => "A128KW"
    A192Kw => "A192KW"
    A256Kw => "A256KW"
    A128GcmKw => "A128GCMKW"
    A192GcmKw => "A192GCMKW"
    A256GcmKw => "A256GCMKW"
    Rsa1_5 => "RSA1_5"
    RsaOaep => "RSA-OAEP"
    RsaOaep256 => "RSA-OAEP-256"
    EcdhEs => "ECDH-ES"
    EcdhEsA128Kw => "ECDH-ES+A128KW"
    EcdhEsA192Kw => "ECDH-ES+A192KW"
    EcdhEsA256Kw => "ECDH-ES+A256KW"
    Pbes2Hs256A128Kw => "PBES2-HS256+A128KW"
    Pbes2Hs384A192Kw => "PBES2-HS384+A192KW"
    Pbes2Hs512A256Kw => "PBES2-HS512+A256KW"
  }
}

///|
/// Read an algorithm by name.
pub fn Alg::of(name : StringView) -> Alg raise Refused {
  match name {
    "dir" => Dir
    "A128KW" => A128Kw
    "A192KW" => A192Kw
    "A256KW" => A256Kw
    "A128GCMKW" => A128GcmKw
    "A192GCMKW" => A192GcmKw
    "A256GCMKW" => A256GcmKw
    "RSA1_5" => Rsa1_5
    "RSA-OAEP" => RsaOaep
    "RSA-OAEP-256" => RsaOaep256
    "ECDH-ES" => EcdhEs
    "ECDH-ES+A128KW" => EcdhEsA128Kw
    "ECDH-ES+A192KW" => EcdhEsA192Kw
    "ECDH-ES+A256KW" => EcdhEsA256Kw
    "PBES2-HS256+A128KW" => Pbes2Hs256A128Kw
    "PBES2-HS384+A192KW" => Pbes2Hs384A192Kw
    "PBES2-HS512+A256KW" => Pbes2Hs512A256Kw
    _ => raise Unsupported("key management " + name.to_owned())
  }
}

///|
/// Whether this algorithm derives the content key instead of wrapping one: under `dir` and
/// ECDH-ES there is nothing on the wire, and there can be only one recipient.
fn Alg::derives(self : Alg) -> Bool {
  match self {
    Dir | EcdhEs => true
    _ => false
  }
}

///|
/// The size of the key this algorithm takes or derives, which is the content algorithm's key
/// size when it derives the content key itself.
fn Alg::key_size(self : Alg, enc : Enc) -> Int32 {
  match self {
    Dir | EcdhEs => enc.key_size()
    A128Kw | A128GcmKw => 16
    A192Kw | A192GcmKw => 24
    A256Kw | A256GcmKw => 32
    EcdhEsA128Kw | Pbes2Hs256A128Kw => 16
    EcdhEsA192Kw | Pbes2Hs384A192Kw => 24
    EcdhEsA256Kw | Pbes2Hs512A256Kw => 32
    Rsa1_5 | RsaOaep | RsaOaep256 => 0
  }
}

///|
/// Why the policy in force refused this algorithm, in the words of the reason it was refused.
fn Alg::refusal_reason(self : Alg) -> String {
  match self {
    Rsa1_5 =>
      "RSA1_5 has no integrity of its own, and the policy in force refuses it"
    RsaOaep => "RSA-OAEP with SHA-1 is refused by the policy in force"
    _ => "the policy in force refuses " + self.name()
  }
}
