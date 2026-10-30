// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// CBOR Object Signing and Encryption (RFC 9052), the three single-recipient structures:
// COSE_Sign1 for a signature, COSE_Mac0 for a MAC, and COSE_Encrypt0 for an AEAD.
//
// Each one is a CBOR array inside a tag, and each one authenticates its *own head header*
// along with the payload, because the header is what says which algorithm was used. A verifier
// that reads the algorithm out of the message and then trusts it has handed the choice to whoever
// wrote the message, so `alg` is an argument here too, exactly as it is in `jwe`.
//
// The structures are the ones with one signer, one MAC or one recipient. The multi-recipient forms
// are a different shape of the same idea and are not written here.

///|
/// Why a message could not be made or opened.
pub(all) suberror Refused {
  Malformed(String)
  Unsupported(String)
  /// The signature or MAC did not verify, or the AEAD would not open.
  Signature
  /// The key is the wrong size or the wrong kind for the algorithm.
  Key
  /// A claim set whose `exp` has passed, at the moment the caller named.
  Expired(at~ : Int64)
  /// A claim set whose `nbf` has not arrived yet.
  TooEarly(at~ : Int64)
} derive(Eq, Debug)

///|
/// The algorithm, by its COSE identifier (RFC 9053).
///
/// One enumeration covers signing, MAC and encryption because a COSE header names all three in the
/// same `alg` label; which of them a value means is decided by the structure it appears in, and a
/// value that cannot be that structure's is refused.
pub(all) enum Alg {
  /// ECDSA with SHA-256, identifier -7.
  Es256
  /// EdDSA over Ed25519, identifier -8.
  EdDsa
  /// RSASSA-PKCS1-v1_5 with SHA-256, identifier -257.
  Rs256
  /// HMAC with SHA-256, identifier 5.
  Hs256
  /// AES-GCM, identifiers 1, 2 and 3.
  A128Gcm
  A192Gcm
  A256Gcm
} derive(Eq, Debug)

///|
/// The identifier as it is written in a header.
fn Alg::id(self : Alg) -> Int64 {
  match self {
    Es256 => -7L
    EdDsa => -8L
    Rs256 => -257L
    Hs256 => 5L
    A128Gcm => 1L
    A192Gcm => 2L
    A256Gcm => 3L
  }
}

///|
fn Alg::of_id(number : Int64) -> Alg raise Refused {
  match number {
    -7L => Es256
    -8L => EdDsa
    -257L => Rs256
    5L => Hs256
    1L => A128Gcm
    2L => A192Gcm
    3L => A256Gcm
    _ => raise Unsupported("algorithm identifier \{number}")
  }
}

///|
/// The key length an AES-GCM identifier wants.
fn Alg::key_size(self : Alg) -> Int32 raise Refused {
  match self {
    A128Gcm => 16
    A192Gcm => 24
    A256Gcm => 32
    _ => raise Malformed("this identifier is not an encryption algorithm")
  }
}

///|
/// The algorithm's name as JOSE spells it, for messages and logs; on the wire
/// COSE writes the integer identifier instead.
pub fn Alg::name(self : Alg) -> String {
  match self {
    Es256 => "ES256"
    EdDsa => "EdDSA"
    Rs256 => "RS256"
    Hs256 => "HS256"
    A128Gcm => "A128GCM"
    A192Gcm => "A192GCM"
    A256Gcm => "A256GCM"
  }
}

// ------------------------------------------------------------------------ headers

///|
/// The head header: the algorithm, and whatever else the caller has to say, as octets.
///
/// Everything goes in the head header and the unhead one stays empty. A label in both is
/// a message two parsers can disagree about, and RFC 9052 §3.1 forbids it; keeping one of them
/// empty means there is nothing to disagree about.
fn header(alg : Alg, kid : BytesView?, iv : BytesView?) -> Bytes {
  let pairs : Array[(@cbor.Value, @cbor.Value)] = [(Int(1), Int(alg.id()))]
  if kid is Some(k) {
    pairs.push((Int(4), Bytes(k.to_owned())))
  }
  if iv is Some(v) {
    pairs.push((Int(5), Bytes(v.to_owned())))
  }
  @cbor.encode(Map(pairs))
}

///|
/// The algorithm a head header names, checked against the one the caller expects.
fn header_alg(head : Bytes, want : Alg) -> Alg raise Refused {
  let value = @cbor.decode(head[:]) catch {
    Malformed(m) => raise Malformed("the head header: " + m)
    Unsupported(m) => raise Unsupported("the head header: " + m)
  }
  let named = match value.get(Int(1)) {
    Some(held) =>
      match held.int() {
        Some(number) => Alg::of_id(number)
        None => raise Malformed("the head header's algorithm is not an integer")
      }
    None => raise Malformed("the head header names no algorithm")
  }
  if named != want {
    raise Malformed("the message is " + named.name() + ", not " + want.name())
  }
  named
}

// ------------------------------------------------------------------------ Sign1

///|
/// The byte string a COSE_Sign1 signature is computed over (RFC 9052 §4.4).
fn signature_structure(
  head : Bytes,
  external : BytesView,
  payload : BytesView,
) -> Bytes {
  @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(head),
      Bytes(external.to_owned()),
      Bytes(payload.to_owned()),
    ]),
  )
}

///|
/// Sign a payload into a COSE_Sign1, wrapped in its tag.
///
/// `alg` is not consulted to choose a key — the signer knows its own — but it is written into the
/// head header and it must be the algorithm the signer actually produces, or the message
/// names something it is not. `external` is the additional data of RFC 9052 §4.4, which a protocol
/// uses to bind a message to its context; the empty byte string is the usual choice.
pub fn sign1(
  payload : BytesView,
  alg~ : Alg,
  signer : &@spec.Signer,
  kid~ : BytesView? = None,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  match alg {
    A128Gcm | A192Gcm | A256Gcm =>
      raise Malformed("a signature is not made with " + alg.name())
    _ => ()
  }
  let head = header(alg, kid, None)
  let signature = signer.sign(signature_structure(head, external, payload)[:])
  @cbor.encode(
    Tag(
      18UL,
      Array([Bytes(head), Map([]), Bytes(payload.to_owned()), Bytes(signature)]),
    ),
  )
}

///|
/// A parsed COSE message: the head header as it arrived, the payload, and whatever else the
/// structure carries.
pub(all) struct Message {
  /// The head header octets, kept as received: a signature is over these and not over a
  /// re-encoding of what they say.
  head : Bytes
  payload : Bytes
  /// The signature of a COSE_Sign1, or the tag of a COSE_Mac0, or the ciphertext of a
  /// COSE_Encrypt0.
  tail : Bytes
} derive(Eq, Debug)

///|
/// Read one of the three single-recipient structures, checking its tag and its shape.
///
/// `tag` is the number the caller expects, so a COSE_Mac0 handed to a verifier of signatures is
/// refused rather than verified under the wrong rule.
pub fn parse(octets : BytesView, tag~ : UInt64) -> Message raise Refused {
  let value = @cbor.decode(octets) catch {
    Malformed(m) => raise Malformed(m)
    Unsupported(m) => raise Unsupported(m)
  }
  let body = match value {
    Tag(number, inner) => {
      if number != tag {
        raise Malformed("a tag of \{number}, not \{tag}")
      }
      inner
    }
    // A message without its tag is what some writers produce, and the shape still tells the
    // three structures apart, so it is accepted rather than refused over a self-describing tag
    // that carries no security.
    _ => value
  }
  // A COSE_Encrypt0 is `[protected, unprotected, ciphertext]` and the other two are the same with
  // the payload in front of the signature or the tag, so the count is what tells them apart.
  let encrypted = tag == 16UL
  let count = if encrypted { 3 } else { 4 }
  guard body is Array(items) && items.length() == count else {
    raise Malformed("a single-recipient structure is \{count} items")
  }
  let head = bytes_at(body, 0)
  let payload = if encrypted {
    b"" // the payload is the ciphertext, and the ciphertext is in the tail
  } else {
    // `[protected, unprotected, payload, signature]`: the payload is third, after the two headers.
    bytes_at(body, 2)
  }
  let tail = bytes_at(body, count - 1)
  { head, payload, tail, }
}

///|
/// The octets at an index of an array, when there are some and they are a byte string.
fn bytes_at(body : @cbor.Value, at : Int32) -> Bytes raise Refused {
  guard body is Array(items) else { raise Malformed("not an array") }
  if at >= items.length() {
    raise Malformed("an item at \{at}, where the array has \{items.length()}")
  }
  guard items[at] is Bytes(octets) else {
    raise Malformed("item \{at} is not a byte string")
  }
  octets
}

///|
/// Check a COSE_Sign1 and hand back its payload.
pub fn verify1(
  octets : BytesView,
  alg~ : Alg,
  verifier : &@spec.Verifier,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  let message = parse(octets, tag=18UL)
  header_alg(message.head, alg) |> ignore
  let structure = signature_structure(message.head, external, message.payload)
  if !verifier.verify(structure[:], message.tail[:]) {
    raise Signature
  }
  message.payload
}

// ------------------------------------------------------------------------ Mac0

///|
/// The byte string a COSE_Mac0 tag is computed over (RFC 9052 §6.3).
fn mac_structure(
  head : Bytes,
  external : BytesView,
  payload : BytesView,
) -> Bytes {
  @cbor.encode(
    Array([
      Text("MAC0"),
      Bytes(head),
      Bytes(external.to_owned()),
      Bytes(payload.to_owned()),
    ]),
  )
}

///|
/// A keyed MAC, standing in as both signer and verifier, the way `jwt.mac` does: it takes a factory
/// because one MAC state cannot authenticate two messages and a key outlives the message it was
/// used on.
pub struct Keyed {
  make : () -> &@spec.Mac
}

///|
/// A MAC factory as a `Keyed`, which makes and checks COSE_Mac0 tags.
pub fn mac(make : () -> &@spec.Mac) -> Keyed {
  { make, }
}

///|
pub extend Keyed with @spec.Signer::{sign}

///|
pub impl @spec.Signer for Keyed with fn sign(self : Keyed, msg : BytesView) -> Bytes {
  let m = (self.make)()
  m.write(msg)
  m.finish()
}

///|
pub extend Keyed with @spec.Verifier::{verify}

///|
/// Compared in constant time, so the answer does not leak the right tag one octet at a time.
pub impl @spec.Verifier for Keyed with fn verify(
  self : Keyed,
  msg : BytesView,
  tag : BytesView,
) -> Bool {
  let m = (self.make)()
  m.write(msg)
  @spec.eq(m.finish()[:], tag)
}

///|
/// MAC a payload into a COSE_Mac0.
pub fn mac0(
  payload : BytesView,
  alg~ : Alg,
  tagger : &@spec.Signer,
  kid~ : BytesView? = None,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  if alg != Hs256 {
    raise Unsupported("a MAC with " + alg.name())
  }
  let head = header(alg, kid, None)
  let tag = tagger.sign(mac_structure(head, external, payload)[:])
  @cbor.encode(
    Tag(
      17UL,
      Array([Bytes(head), Map([]), Bytes(payload.to_owned()), Bytes(tag)]),
    ),
  )
}

///|
/// Check a COSE_Mac0 and hand back its payload.
pub fn verify_mac0(
  octets : BytesView,
  alg~ : Alg,
  verifier : &@spec.Verifier,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  let message = parse(octets, tag=17UL)
  header_alg(message.head, alg) |> ignore
  let structure = mac_structure(message.head, external, message.payload)
  if !verifier.verify(structure[:], message.tail[:]) {
    raise Signature
  }
  message.payload
}

// ------------------------------------------------------------------------ Encrypt0

///|
/// The additional data of a COSE_Encrypt0 (RFC 9052 §5.3): the structure's name, the head
/// header and the external data, and not the payload, which is what is being encrypted.
fn encrypt_structure(head : Bytes, external : BytesView) -> Bytes {
  @cbor.encode(
    Array([Text("Encrypt0"), Bytes(head), Bytes(external.to_owned())]),
  )
}

///|
/// Encrypt a payload into a COSE_Encrypt0, under a key the caller supplies.
///
/// The nonce is not generated here for the reason no other package generates one: entropy is the
/// caller's to find, and a library that quietly reuses a nonce under a long-lived key is worse than
/// one that asks.
pub fn encrypt0(
  payload : BytesView,
  alg~ : Alg,
  key~ : BytesView,
  iv~ : BytesView,
  kid~ : BytesView? = None,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  if key.length() != alg.key_size() {
    raise Key
  }
  if iv.length() != 12 {
    raise Malformed(
      "an IV of \{iv.length()} octets for GCM, which wants twelve",
    )
  }
  let head = header(alg, kid, Some(iv))
  let aad = encrypt_structure(head, external)
  let cipher = @aes.Cipher::new(key) catch { _ => raise Key }
  let gcm = @gcm.Gcm::new(cipher, tag=16) catch {
    _ => raise Malformed("GCM refused the parameters")
  }
  let body = gcm.seal(nonce=iv, plain=payload, aad=aad[:])
  @cbor.encode(Tag(16UL, Array([Bytes(head), Map([]), Bytes(body)])))
}

///|
/// Open a COSE_Encrypt0: the nonce comes from the head header, which is authenticated, so a
/// message whose header was changed does not open.
pub fn decrypt0(
  octets : BytesView,
  alg~ : Alg,
  key~ : BytesView,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  let message = parse(octets, tag=16UL)
  header_alg(message.head, alg) |> ignore
  if key.length() != alg.key_size() {
    raise Key
  }
  let header_value = @cbor.decode(message.head[:]) catch {
    Malformed(m) => raise Malformed("the head header: " + m)
    Unsupported(m) => raise Unsupported("the head header: " + m)
  }
  let iv = match header_value.get(Int(5)) {
    Some(held) =>
      match held.bytes() {
        Some(octets) => octets
        None => raise Malformed("the head header's IV is not a byte string")
      }
    None => raise Malformed("the head header carries no IV")
  }
  if iv.length() != 12 {
    raise Malformed(
      "an IV of \{iv.length()} octets for GCM, which wants twelve",
    )
  }
  let aad = encrypt_structure(message.head, external)
  let cipher = @aes.Cipher::new(key) catch { _ => raise Key }
  let gcm = @gcm.Gcm::new(cipher, tag=16) catch {
    _ => raise Malformed("GCM refused the parameters")
  }
  gcm.open(nonce=iv[:], cipher=message.tail[:], aad=aad[:]) catch {
    _ => raise Signature
  }
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Alg with Eq::{equal, not_equal}

///|
pub extend Alg with Debug::{to_repr}

///|
pub extend Message with Eq::{equal, not_equal}

///|
pub extend Message with Debug::{to_repr}
