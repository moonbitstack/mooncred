// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A JWE is two keys doing two jobs. A key-management algorithm puts a content-encryption key
// somewhere the recipient can reach it — wrapped under a shared secret, encrypted to an RSA key,
// derived from a password or from a curve — and the content-encryption algorithm spends that key
// on the payload. `dir` is the degenerate case where there is only one key and it is both.
//
// The header is authenticated, not just carried: it is the additional data of the AEAD and the
// first field of the CBC-HMAC tag, so an attacker who changes `alg` changes what verifies.

///|
/// Why a token could not be sealed or opened.
#derive(Eq, Debug)
pub(all) suberror Refused {
  /// The message is not a token, or a field is of the wrong shape or length.
  Malformed(String)
  /// The message asks for something this library does not do, or does not do unless asked.
  Unsupported(String)
  /// The key does not open the token: the wrapped key would not unwrap, or the tag did not
  /// match.
  Key
}

///|
/// The content-encryption algorithm: authenticated encryption over the payload.
#derive(Eq, Debug)
pub(all) enum Enc {
  A128Gcm
  A192Gcm
  A256Gcm
  /// AES-CBC with HMAC-SHA-256, the tag truncated to sixteen octets (RFC 7518 §5.2.3).
  A128CbcHs256
  A192CbcHs384
  A256CbcHs512
}

///|
/// The name this algorithm goes by in a header.
pub fn Enc::name(self : Enc) -> String {
  match self {
    A128Gcm => "A128GCM"
    A192Gcm => "A192GCM"
    A256Gcm => "A256GCM"
    A128CbcHs256 => "A128CBC-HS256"
    A192CbcHs384 => "A192CBC-HS384"
    A256CbcHs512 => "A256CBC-HS512"
  }
}

///|
/// Read a content-encryption algorithm by name.
pub fn Enc::of(name : StringView) -> Enc raise Refused {
  match name {
    "A128GCM" => A128Gcm
    "A192GCM" => A192Gcm
    "A256GCM" => A256Gcm
    "A128CBC-HS256" => A128CbcHs256
    "A192CBC-HS384" => A192CbcHs384
    "A256CBC-HS512" => A256CbcHs512
    _ => raise Unsupported("content encryption " + name.to_owned())
  }
}

///|
pub extend Enc with Eq::{equal, not_equal}

///|
pub extend Enc with Debug::{to_repr}

///|
/// The size of a content-encryption key. For the CBC-HMAC algorithms this is the MAC key and the
/// AES key together, the MAC key first.
fn Enc::key_size(self : Enc) -> Int32 {
  match self {
    A128Gcm => 16
    A192Gcm => 24
    A256Gcm => 32
    A128CbcHs256 => 32
    A192CbcHs384 => 48
    A256CbcHs512 => 64
  }
}

///|
/// The IV or nonce length: twelve for GCM, sixteen for CBC.
fn Enc::iv_size(self : Enc) -> Int32 {
  match self {
    A128Gcm | A192Gcm | A256Gcm => 12
    _ => 16
  }
}

///|
/// The authentication tag length.
fn Enc::tag_size(self : Enc) -> Int32 {
  match self {
    A128Gcm | A192Gcm | A256Gcm => 16
    A128CbcHs256 => 16
    A192CbcHs384 => 24
    A256CbcHs512 => 32
  }
}

///|
/// Seal a payload under a key, into the compact serialisation: five base64url parts, the header
/// first, so the recipient knows what to do before it does anything.
///
/// `cek` is the content-encryption key and `iv` the nonce; both are the caller's, for the reason
/// this library has no generator. Under `dir` and ECDH-ES the key is derived and `cek` must be
/// left out; under any other algorithm it is required and must be `enc.key_size` octets.
///
/// The randomness an algorithm needs is an argument too: `seed` is what RSA's padding and
/// OAEP's mask draw, `salt` and `count` are the PBES2 derivation, `wrap_iv` is the nonce an
/// AES-GCM wrap uses, and `ephemeral` is the ECDH-ES private scalar. Draw each of them fresh
/// for every message; the tests pin them because a vector has to be reproducible.
pub fn encrypt(
  plain : BytesView,
  key~ : Key,
  alg~ : Alg,
  enc~ : Enc,
  cek? : Bytes,
  iv~ : BytesView,
  seed~ : BytesView = b"",
  header~ : Map[String, Json] = Map([]),
  salt? : Bytes,
  count? : Int32,
  wrap_iv? : Bytes,
  ephemeral? : Bytes,
  compress~ : Bool = false,
  policy~ : Policy = policy,
) -> String raise Refused {
  let recipient : Recipient = {
    ..Recipient::new(alg, key),
    header,
    cek,
    salt,
    count,
    iv: wrap_iv,
    ephemeral,
    seed: if seed.length() > 0 {
      Some(seed.to_owned())
    } else {
      None
    },
  }
  seal_compact(plain, enc~, recipient~, iv~, compress~, policy~)
}

///|
/// The same seal, with the recipient spelled out: what a caller with several of the optional
/// materials in hand wants, and what [`encrypt`] is written in terms of.
pub fn seal_compact(
  plain : BytesView,
  enc~ : Enc,
  recipient~ : Recipient,
  iv~ : BytesView,
  compress~ : Bool = false,
  policy~ : Policy = policy,
) -> String raise Refused {
  if iv.length() != enc.iv_size() {
    raise Malformed(
      "an IV of \{iv.length()} octets for " +
      enc.name() +
      ", which wants \{enc.iv_size()}",
    )
  }
  let (content_key, wrapped, parameters) = seal_recipient(
    enc, recipient, policy,
  )
  // The order the parameters go in: the algorithm, the recipient's name, what the algorithm
  // generated, anything else the caller said, then the content encryption and its compression.
  let fields : Map[String, Json] = Map([])
  fields["alg"] = Json::string(recipient.alg.name())
  for name, value in recipient.header {
    if name == "kid" {
      fields[name] = value
    }
  }
  for name, value in parameters {
    fields[name] = value
  }
  for name, value in recipient.header {
    if name != "kid" && name != "alg" && name != "enc" && name != "zip" {
      fields[name] = value
    }
  }
  fields["enc"] = Json::string(enc.name())
  if compress {
    fields["zip"] = Json::string("DEF")
  }
  let text = @json.dumps(Json::object(fields))
  let head = b64(@utf8.encode(text))
  let body = if compress { squeeze(plain) } else { plain.to_owned() }
  let (cipher, tag) = content_seal(
    enc,
    content_key,
    iv,
    body[:],
    @utf8.encode(head),
  )
  head +
  "." +
  b64(wrapped) +
  "." +
  b64(iv.to_owned()) +
  "." +
  b64(cipher) +
  "." +
  b64(tag)
}

///|
/// Open a compact token, checking that the header names the algorithms the caller expects.
///
/// The expected `alg` and `enc` are arguments and not read from the header on the caller's behalf
/// for the reason JWT's `none` exists: a recipient that believes whatever the token says about
/// itself can be talked into the weakest algorithm it supports. A token that names another
/// algorithm is `Malformed` rather than opened under the caller's.
///
/// `policy` decides whether the two key-management algorithms that carry a security argument of
/// their own are accepted at all. They are, by default; [`strict`] is the preset that refuses
/// them, and it refuses them here as well as when sealing.
pub fn decrypt(
  text : StringView,
  key~ : Identity,
  alg~ : Alg,
  enc~ : Enc,
  policy~ : Policy = policy,
) -> Bytes raise Refused {
  let parts = split(text)
  let (head, wrapped, iv, cipher, tag) = match parts {
    [h, w, i, c, t] => (h, w, i, c, t)
    _ => raise Malformed("a compact JWE is five dot-separated parts")
  }
  let fields = object_of(b64_decode(head), "header")
  let named = named_alg(fields)
  let content = named_enc(fields)
  if named != alg {
    raise Malformed("the token is " + named.name() + ", not " + alg.name())
  }
  if content != enc {
    raise Malformed("the token is " + content.name() + ", not " + enc.name())
  }
  let content_key = open_recipient(
    enc,
    alg,
    key,
    b64_decode(wrapped),
    fields,
    policy,
  )
  let plain = content_open(
    enc,
    content_key,
    b64_decode(iv),
    b64_decode(cipher),
    b64_decode(tag),
    @utf8.encode(head),
  )
  match fields.get("zip") {
    Some(_) => loosen(plain, fields)
    None => plain
  }
}

// -------------------------------------------------------------- one recipient

///|
/// Put a content key where one recipient can reach it, and say in the header what was done.
///
/// The content key comes back with the encrypted one because the two algorithms that derive it
/// are also the two that carry nothing.
fn seal_recipient(
  enc : Enc,
  recipient : Recipient,
  policy : Policy,
) -> (Bytes, Bytes, Map[String, Json]) raise Refused {
  let alg = recipient.alg
  if !policy.allows(alg) {
    raise Unsupported(alg.refusal_reason())
  }
  if alg.derives() && recipient.cek is Some(_) {
    raise Malformed(
      alg.name() + " derives the content key; there is none to give",
    )
  }
  let parameters : Map[String, Json] = Map([])
  let content_key = match alg {
    Dir => {
      guard recipient.key is Shared(k) else {
        raise Malformed("dir needs a shared key")
      }
      if k.length() != enc.key_size() {
        raise Malformed("a shared key of the wrong length for " + enc.name())
      }
      k
    }
    EcdhEs => agree_and_derive(recipient, alg, enc, enc.key_size(), parameters)
    _ => given_content_key(recipient, enc)
  }
  let wrapped = match alg {
    Dir | EcdhEs => b""
    A128Kw | A192Kw | A256Kw => {
      guard recipient.key is Shared(k) else {
        raise Malformed(alg.name() + " needs a shared key")
      }
      expect_size(k, alg.key_size(enc), alg)
      wrap(k[:], content_key[:])
    }
    A128GcmKw | A192GcmKw | A256GcmKw => {
      guard recipient.key is Shared(k) else {
        raise Malformed(alg.name() + " needs a shared key")
      }
      expect_size(k, alg.key_size(enc), alg)
      guard recipient.iv is Some(nonce) else {
        raise Malformed(alg.name() + " needs a nonce for its wrap")
      }
      let (cipher, tag) = gcm_kw_wrap(k[:], content_key[:], nonce[:])
      parameters["tag"] = Json::string(b64(tag))
      parameters["iv"] = Json::string(b64(nonce))
      cipher
    }
    Rsa1_5 | RsaOaep | RsaOaep256 => {
      guard recipient.key is Rsa(k) else {
        raise Malformed(alg.name() + " needs an RSA key")
      }
      guard recipient.seed is Some(seed) else {
        raise Malformed(alg.name() + " needs a seed for its padding")
      }
      rsa_wrap(alg, k, content_key[:], seed[:])
    }
    EcdhEsA128Kw | EcdhEsA192Kw | EcdhEsA256Kw => {
      let kek = agree_and_derive(
        recipient,
        alg,
        enc,
        alg.key_size(enc),
        parameters,
      )
      wrap(kek[:], content_key[:])
    }
    Pbes2Hs256A128Kw | Pbes2Hs384A192Kw | Pbes2Hs512A256Kw => {
      guard recipient.key is Password(password) else {
        raise Malformed(alg.name() + " needs a password")
      }
      guard recipient.salt is Some(salt) else {
        raise Malformed(alg.name() + " needs a salt")
      }
      guard recipient.count is Some(count) else {
        raise Malformed(alg.name() + " needs an iteration count")
      }
      let kek = pbes2_kek(alg, password[:], salt[:], count)
      parameters["p2s"] = Json::string(b64(salt))
      parameters["p2c"] = Json::number(
        count.to_double(),
        repr=count.to_string(),
      )
      wrap(kek[:], content_key[:])
    }
  }
  (content_key, wrapped, parameters)
}

///|
/// Recover the content key of one recipient.
fn open_recipient(
  enc : Enc,
  alg : Alg,
  identity : Identity,
  wrapped : BytesView,
  header : Map[String, Json],
  policy : Policy,
) -> Bytes raise Refused {
  if !policy.allows(alg) {
    raise Unsupported(alg.refusal_reason())
  }
  let key = match alg {
    Dir => {
      guard identity is Shared(k) else {
        raise Malformed("dir needs a shared key")
      }
      if k.length() != enc.key_size() {
        raise Malformed("a shared key of the wrong length for " + enc.name())
      }
      k
    }
    EcdhEs => agree_and_recover(enc, alg, identity, enc.key_size(), header)
    A128Kw | A192Kw | A256Kw => {
      guard identity is Shared(k) else {
        raise Malformed(alg.name() + " needs a shared key")
      }
      expect_size(k, alg.key_size(enc), alg)
      unwrap(k[:], wrapped) catch {
        _ => raise Key
      }
    }
    A128GcmKw | A192GcmKw | A256GcmKw => {
      guard identity is Shared(k) else {
        raise Malformed(alg.name() + " needs a shared key")
      }
      expect_size(k, alg.key_size(enc), alg)
      let nonce = match header.get("iv") {
        Some(String(text)) => unwrap_b64(text)
        _ => raise Malformed(alg.name() + " says no nonce")
      }
      let tag = match header.get("tag") {
        Some(String(text)) => unwrap_b64(text)
        _ => raise Malformed(alg.name() + " says no tag")
      }
      gcm_kw_unwrap(k[:], wrapped, tag[:], nonce[:])
    }
    Rsa1_5 | RsaOaep | RsaOaep256 => {
      guard identity is Rsa(k) else {
        raise Malformed(alg.name() + " needs an RSA key")
      }
      rsa_unwrap(alg, k, wrapped)
    }
    EcdhEsA128Kw | EcdhEsA192Kw | EcdhEsA256Kw => {
      let kek = agree_and_recover(enc, alg, identity, alg.key_size(enc), header)
      unwrap(kek[:], wrapped) catch {
        _ => raise Key
      }
    }
    Pbes2Hs256A128Kw | Pbes2Hs384A192Kw | Pbes2Hs512A256Kw => {
      guard identity is Password(password) else {
        raise Malformed(alg.name() + " needs a password")
      }
      let salt = match header.get("p2s") {
        Some(String(text)) => unwrap_b64(text)
        _ => raise Malformed(alg.name() + " says no salt")
      }
      let count = match header.get("p2c") {
        Some(Number(value, ..)) => value.to_int()
        _ => raise Malformed(alg.name() + " says no iteration count")
      }
      let kek = pbes2_kek(alg, password[:], salt[:], count)
      unwrap(kek[:], wrapped) catch {
        _ => raise Key
      }
    }
  }
  if key.length() != enc.key_size() {
    raise Key
  }
  key
}

///|
/// The content key a recipient was given, checked against the content algorithm.
fn given_content_key(recipient : Recipient, enc : Enc) -> Bytes raise Refused {
  match recipient.cek {
    Some(cek) =>
      if cek.length() != enc.key_size() {
        raise Malformed("a content key of the wrong length for " + enc.name())
      } else {
        cek
      }
    None =>
      raise Malformed("a content key is needed under " + recipient.alg.name())
  }
}

///|
fn expect_size(key : BytesView, want : Int32, alg : Alg) -> Unit raise Refused {
  if key.length() != want {
    raise Malformed(
      "a \{alg.name()} key is \{want} octets, not \{key.length()}",
    )
  }
}

///|
/// Agree a secret with the recipient and derive from it, for sealing.
fn agree_and_derive(
  recipient : Recipient,
  alg : Alg,
  enc : Enc,
  len : Int32,
  parameters : Map[String, Json],
) -> Bytes raise Refused {
  guard recipient.key is Agreement(curve, point) else {
    raise Malformed(alg.name() + " needs an elliptic-curve public key")
  }
  guard recipient.ephemeral is Some(scalar) else {
    raise Malformed(alg.name() + " needs an ephemeral key")
  }
  let z = agree(scalar[:], point, curve)
  parameters["epk"] = Json::object(epk_of(scalar[:], curve))
  let apu = party_info(recipient.header, "apu")
  let apv = party_info(recipient.header, "apv")
  let algid = if alg is EcdhEs { enc.name() } else { alg.name() }
  concat_key(z[:], algid[:], apu[:], apv[:], len * 8)
}

///|
/// Agree a secret with the sender and derive from it, for opening.
fn agree_and_recover(
  enc : Enc,
  alg : Alg,
  identity : Identity,
  len : Int32,
  header : Map[String, Json],
) -> Bytes raise Refused {
  guard identity is Agreement(curve, scalar) else {
    raise Malformed(alg.name() + " needs an elliptic-curve private key")
  }
  let epk = match header.get("epk") {
    Some(Object(fields)) => fields
    _ => raise Malformed(alg.name() + " says no ephemeral key")
  }
  let (theirs, point) = point_of_epk(epk)
  if theirs != curve {
    raise Malformed("an ephemeral key on another curve")
  }
  let z = agree(scalar[:], point[:], curve)
  let apu = party_info(header, "apu")
  let apv = party_info(header, "apv")
  let algid = if alg is EcdhEs { enc.name() } else { alg.name() }
  concat_key(z[:], algid[:], apu[:], apv[:], len * 8)
}

// --------------------------------------------------------------- compression

///|
/// `zip: DEF`: the payload travels deflated (RFC 1951), which is what makes a JWE of a
/// document smaller than the document.
fn squeeze(plain : BytesView) -> Bytes {
  @deflate.deflate(plain)
}

///|
fn loosen(plain : Bytes, fields : Map[String, Json]) -> Bytes raise Refused {
  match fields.get("zip") {
    Some(String("DEF")) =>
      @deflate.inflate(plain[:]) catch {
        _ => raise Malformed("the payload does not inflate")
      }
    Some(String(other)) => raise Unsupported("compression " + other)
    Some(_) => raise Malformed("zip is a string")
    None => plain
  }
}

// -------------------------------------------------------------- content crypto

///|
/// Encrypt and authenticate the payload: `(ciphertext, tag)`.
fn content_seal(
  enc : Enc,
  cek : Bytes,
  iv : BytesView,
  plain : BytesView,
  aad : BytesView,
) -> (Bytes, Bytes) raise Refused {
  match enc {
    A128Gcm | A192Gcm | A256Gcm => {
      let cipher = @aes.Cipher::new(cek[:]) catch {
        _ => raise Malformed("an AES key of the wrong length")
      }
      let gcm = @gcm.Gcm::new(cipher, tag=16) catch {
        _ => raise Malformed("GCM refused the parameters")
      }
      let whole = gcm.seal(nonce=iv, plain~, aad~)
      let cut = whole.length() - 16
      (whole[:cut].to_owned(), whole[cut:].to_owned())
    }
    _ => {
      let half = cek.length() / 2
      let mac_key = cek[0:half]
      let cipher = @aes.Cipher::new(cek[half:]) catch {
        _ => raise Malformed("an AES key of the wrong length")
      }
      let body = cbc_encrypt(cipher, iv, plain)
      let tag = cbc_tag(enc, mac_key, aad, iv, body[:])
      (body, tag)
    }
  }
}

///|
/// The inverse: `Key` when the tag does not match, which is how a wrong key and an edited
/// payload are told apart from a good one.
fn content_open(
  enc : Enc,
  cek : Bytes,
  iv : BytesView,
  cipher : BytesView,
  tag : BytesView,
  aad : BytesView,
) -> Bytes raise Refused {
  if tag.length() != enc.tag_size() {
    raise Malformed("a tag of the wrong length for " + enc.name())
  }
  if iv.length() != enc.iv_size() {
    raise Malformed("an IV of the wrong length for " + enc.name())
  }
  match enc {
    A128Gcm | A192Gcm | A256Gcm => {
      let cipher_block = @aes.Cipher::new(cek[:]) catch {
        _ => raise Malformed("an AES key of the wrong length")
      }
      let gcm = @gcm.Gcm::new(cipher_block, tag=16) catch {
        _ => raise Malformed("GCM refused the parameters")
      }
      let joined = Buffer()
      joined.write_bytesview(cipher)
      joined.write_bytesview(tag)
      gcm.open(nonce=iv, cipher=joined.to_bytes()[:], aad~) catch {
        _ => raise Key
      }
    }
    _ => {
      let half = cek.length() / 2
      let want = cbc_tag(enc, cek[0:half], aad, iv, cipher)
      if !same(want[:], tag) {
        raise Key
      }
      let cipher_block = @aes.Cipher::new(cek[half:]) catch {
        _ => raise Malformed("an AES key of the wrong length")
      }
      cbc_decrypt(cipher_block, iv, cipher)
    }
  }
}

///|
/// AES-CBC with PKCS#7 padding, under a key already checked for length.
fn cbc_encrypt(
  cipher : @aes.Cipher,
  iv : BytesView,
  plain : BytesView,
) -> Bytes raise Refused {
  if iv.length() != 16 {
    raise Malformed("an IV of \{iv.length()} octets for a sixteen-octet block")
  }
  let pad = 16 - plain.length() % 16
  let body = Buffer()
  body.write_bytesview(plain)
  for _ in 0..<pad {
    body.write_byte(pad.to_byte())
  }
  let padded = body.to_bytes()
  let out = Buffer()
  let mut chain = iv.to_owned()
  let mut off = 0
  while off < padded.length() {
    let block = Buffer()
    for i in 0..<16 {
      block.write_byte((padded[off + i].to_int() ^ chain[i].to_int()).to_byte())
    }
    let packed = cipher.encrypt(block.to_bytes()[:])
    out.write_bytes(packed[:])
    chain = packed
    off = off + 16
  }
  out.to_bytes()
}

///|
fn cbc_decrypt(
  cipher : @aes.Cipher,
  iv : BytesView,
  body : BytesView,
) -> Bytes raise Refused {
  if body.length() == 0 || body.length() % 16 != 0 {
    raise Malformed("a ciphertext that is not a run of whole blocks")
  }
  if iv.length() != 16 {
    raise Malformed("an IV of \{iv.length()} octets for a sixteen-octet block")
  }
  let out = Buffer()
  let mut chain = iv.to_owned()
  let mut off = 0
  while off < body.length() {
    let block = body[off:off + 16]
    let opened = cipher.decrypt(block)
    for i in 0..<16 {
      out.write_byte((opened[i].to_int() ^ chain[i].to_int()).to_byte())
    }
    chain = block.to_owned()
    off = off + 16
  }
  let padded = out.to_bytes()
  let pad = padded[padded.length() - 1].to_int()
  if pad < 1 || pad > 16 {
    raise Key
  }
  for i in 1..<=pad {
    if padded[padded.length() - i].to_int() != pad {
      raise Key
    }
  }
  padded[:padded.length() - pad].to_owned()
}

///|
/// The CBC-HMAC tag (RFC 7518 §5.2.2.1): HMAC over the additional data, the IV, the ciphertext
/// and the bit length of the additional data, truncated to the algorithm's tag size.
fn cbc_tag(
  enc : Enc,
  mac_key : BytesView,
  aad : BytesView,
  iv : BytesView,
  body : BytesView,
) -> Bytes {
  let h = @hmac.Hmac::new(mac_key, () => hasher(enc))
  h.write(aad)
  h.write(iv)
  h.write(body)
  let bits = aad.length().to_int64() * 8L
  let length = Buffer()
  let mut i = 7
  while i >= 0 {
    length.write_byte(((bits >> (i * 8)) & 0xffL).to_byte())
    i = i - 1
  }
  h.write(length.to_bytes()[:])
  let full = h.finish()
  full[:enc.tag_size()].to_owned()
}

///|
fn hasher(enc : Enc) -> &@spec.Hash {
  match enc {
    A128CbcHs256 => (@sha2.Hasher::new(kind=Sha256) : &@spec.Hash)
    A192CbcHs384 => (@sha2.Hasher::new(kind=Sha384) : &@spec.Hash)
    A256CbcHs512 => (@sha2.Hasher::new(kind=Sha512) : &@spec.Hash)
    _ => (@sha2.Hasher::new(kind=Sha256) : &@spec.Hash)
  }
}

// ------------------------------------------------------------------ the pieces

///|
/// A header object read from bytes.
fn object_of(raw : Bytes, what : String) -> Map[String, Json] raise Refused {
  let text = @utf8.decode(raw) catch {
    _ => raise Malformed("the \{what} is not UTF-8")
  }
  let value = @json.loads(text[:]) catch {
    _ => raise Malformed("the \{what} is not JSON")
  }
  match value {
    Object(fields) => fields
    _ => raise Malformed("the \{what} is not an object")
  }
}

///|
fn named_alg(fields : Map[String, Json]) -> Alg raise Refused {
  match fields.get("alg") {
    Some(String(name)) => Alg::of(name[:])
    _ => raise Malformed("the header names no algorithm")
  }
}

///|
fn named_enc(fields : Map[String, Json]) -> Enc raise Refused {
  match fields.get("enc") {
    Some(String(name)) => Enc::of(name[:])
    _ => raise Malformed("the header names no content encryption")
  }
}

///|
/// base64url without padding, the only encoding the compact serialisation uses.
fn b64(bytes : BytesView) -> String {
  @base64.encode(bytes, kind=Url, padding=false)
}

///|
fn b64_decode(text : StringView) -> Bytes raise Refused {
  @base64.decode(text, kind=Url) catch {
    _ => raise Malformed("a part that is not base64url")
  }
}

///|
/// A compact JWE split at its dots.
fn split(text : StringView) -> Array[String] {
  let out : Array[String] = []
  let part = StringBuilder()
  for c in text {
    if c == '.' {
      out.push(part.to_string())
      part.reset()
    } else {
      part.write_char(c)
    }
  }
  out.push(part.to_string())
  out
}

///|
/// Two octet strings are equal, read to the end either way.
fn same(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}
