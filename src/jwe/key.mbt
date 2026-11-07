// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What a message is sealed to and opened with, and the two records that carry the material a
// key-management algorithm needs beyond the key itself: a nonce for the ones that draw one, a
// salt and an iteration count for the ones derived from a password, a scalar for the one that
// agrees a key.

///|
/// What a token is sealed to.
pub(all) enum Key {
  /// A shared secret: `dir` and the AES wrapping algorithms.
  Shared(Bytes)
  /// An RSA public key: `RSA1_5`, `RSA-OAEP` and `RSA-OAEP-256`.
  Rsa(@rsa.PublicKey)
  /// A password: the PBES2 algorithms.
  Password(Bytes)
  /// An elliptic-curve public point, `04 ∥ X ∥ Y`, with the curve it lies on: the ECDH-ES
  /// algorithms.
  Agreement(@curve.Curve, Bytes)
}

///|
/// A key prints as what it is and how big it is, never as its octets: a debug line that
/// carried key material is how a private key ends up in a log.
pub impl Debug for Key with fn to_repr(self : Key) -> Repr {
  match self {
    Shared(k) => Repr::opaque_("Shared", size_of(k.length()))
    Rsa(k) => Repr::opaque_("Rsa", size_of(k.size() * 8))
    Password(p) => Repr::opaque_("Password", size_of(p.length()))
    Agreement(_, point) => Repr::opaque_("Agreement", size_of(point.length()))
  }
}

///|
/// What a token is opened with: the private half of one of the above.
pub(all) enum Identity {
  Shared(Bytes)
  Rsa(@rsa.PrivateKey)
  Password(Bytes)
  /// The private scalar, big-endian and as long as the curve: ECDH-ES.
  Agreement(@curve.Curve, Bytes)
}

///|
pub extend Key with Debug::{to_repr}

///|
pub extend Identity with Debug::{to_repr}

///|
/// The same rule for the private half.
pub impl Debug for Identity with fn to_repr(self : Identity) -> Repr {
  match self {
    Shared(k) => Repr::opaque_("Shared", size_of(k.length()))
    Rsa(k) => Repr::opaque_("Rsa", size_of(k.size() * 8))
    Password(p) => Repr::opaque_("Password", size_of(p.length()))
    Agreement(_, scalar) => Repr::opaque_("Agreement", size_of(scalar.length()))
  }
}

///|
pub extend Recipient with Debug::{to_repr}

///|
fn size_of(count : Int32) -> Repr {
  Repr::integer(count.to_string())
}

///|
/// One recipient of a token being sealed.
///
/// A record rather than eleven arguments, because the material an algorithm needs is not the
/// same for any two of them: `iv` is the AES-GCM nonce of `A256GCMKW`, `salt` and `count` are
/// the PBES2 derivation parameters, `ephemeral` is the ECDH-ES scalar, and `seed` is the
/// randomness RSA's padding needs. A field an algorithm does not use is `None`, and one it
/// does use and is not given is refused rather than filled in — this library holds no source
/// of randomness.
///
/// `cek` is the content-encryption key. Under `dir` and ECDH-ES it must be absent, because
/// those derive it; under everything else it is required, and a message with several
/// recipients gives the same one to each so that one ciphertext serves them all.
#derive(Debug)
pub(all) struct Recipient {
  /// How this recipient's copy of the content key is protected.
  alg : Alg
  /// What it is protected to.
  key : Key
  /// Header parameters that travel with this recipient, `kid` above all.
  header : Map[String, Json]
  cek : Bytes?
  /// The PBES2 salt, before the algorithm name is mixed in.
  salt : Bytes?
  /// The PBES2 iteration count. RFC 7518 §4.8.1.2 sets a floor of 1000.
  count : Int32?
  /// The AES-GCM nonce of `A*GCMKW`.
  iv : Bytes?
  /// The ECDH-ES ephemeral private scalar.
  ephemeral : Bytes?
  /// The randomness RSA's padding draws, and OAEP's seed.
  seed : Bytes?
}

///|
/// A recipient with nothing but its algorithm and key: everything else is `None`.
pub fn Recipient::new(alg : Alg, key : Key) -> Recipient {
  {
    alg,
    key,
    header: Map([]),
    cek: None,
    salt: None,
    count: None,
    iv: None,
    ephemeral: None,
    seed: None,
  }
}

///|
/// A key a caller is willing to open a message with: one algorithm and the material for it.
///
/// Several are offered at once, because a token addressed to several recipients names a
/// different algorithm in each of their headers, and the reader does not know which of them is
/// his until one of them opens. Nothing is tried that the caller did not offer.
pub(all) struct Unseal {
  alg : Alg
  key : Identity
}

///|
pub fn Unseal::new(alg : Alg, key : Identity) -> Unseal {
  { alg, key, }
}

///|
/// What came out of a message that opened.
pub(all) struct Opened {
  /// The payload, after any decompression.
  plain : Bytes
  /// The additional authenticated data the sender gave, empty when there was none.
  aad : Bytes
  /// The header of the recipient that opened it, with the shared protected and unprotected
  /// headers merged in: what the sender said about this message.
  header : Map[String, Json]
  /// Which recipient opened it, counting from zero.
  index : Int32
}
