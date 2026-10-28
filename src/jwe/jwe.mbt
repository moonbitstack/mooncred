// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A JWE is two keys doing two jobs. A key-management algorithm puts a content-encryption key
// somewhere the recipient can reach it — wrapped under a shared secret, encrypted to an RSA key —
// and the content-encryption algorithm spends that key on the payload. `dir` is the degenerate
// case where there is only one key and it is both.
//
// The header is authenticated, not just carried: it is the additional data of the AEAD and the
// first field of the CBC-HMAC tag, so an attacker who changes `alg` changes what verifies.

///|
/// Why a token could not be sealed or opened.
pub(all) suberror Refused {
  Malformed(String)
  Unsupported(String)
  /// The key does not open the token: the wrapped key would not unwrap, or the tag did not match.
  Key
} derive(Eq, Debug)

///|
/// The key-management algorithm: how the content-encryption key reaches the recipient.
pub(all) enum Alg {
  /// The shared key is the content-encryption key: no wrapped key at all.
  Dir
  A128Kw
  A192Kw
  A256Kw
  RsaOaep256
} derive(Eq, Debug)

///|
/// The content-encryption algorithm: authenticated encryption over the payload.
pub(all) enum Enc {
  A128Gcm
  A192Gcm
  A256Gcm
  /// AES-CBC with HMAC-SHA-256, the tag truncated to sixteen octets (RFC 7518 §5.2.3).
  A128CbcHs256
  A192CbcHs384
  A256CbcHs512
} derive(Eq, Debug)

///|
/// What a token is sealed to.
pub(all) enum Key {
  Shared(Bytes)
  Rsa(@rsa.PublicKey)
}

///|
/// What a token is opened with.
pub(all) enum Identity {
  Shared(Bytes)
  Rsa(@rsa.PrivateKey)
}

///|
fn Alg::name(self : Alg) -> String {
  match self {
    Dir => "dir"
    A128Kw => "A128KW"
    A192Kw => "A192KW"
    A256Kw => "A256KW"
    RsaOaep256 => "RSA-OAEP-256"
  }
}

///|
fn Enc::name(self : Enc) -> String {
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
fn alg_of(name : StringView) -> Alg raise Refused {
  match name {
    "dir" => Dir
    "A128KW" => A128Kw
    "A192KW" => A192Kw
    "A256KW" => A256Kw
    "RSA-OAEP-256" => RsaOaep256
    _ => raise Unsupported("key management " + name.to_owned())
  }
}

///|
fn enc_of(name : StringView) -> Enc raise Refused {
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
/// this library has no generator. Under `dir` the CEK is the shared key and `cek` must be `None`;
/// under any other algorithm it is required and must be `cek_size` octets. `seed` is what
/// RSA-OAEP-256 needs to make its padding: the algorithm is randomised, and the randomness has to
/// come from somewhere that is not here.
pub fn encrypt(
  plain : BytesView,
  key~ : Key,
  alg~ : Alg,
  enc~ : Enc,
  cek~ : Bytes? = None,
  iv~ : BytesView,
  seed~ : BytesView = b"",
) -> String raise Refused {
  if iv.length() != enc.iv_size() {
    raise Malformed(
      "an IV of \{iv.length()} octets for " +
      enc.name() +
      ", which wants \{enc.iv_size()}",
    )
  }
  let content_key = match (alg, key) {
    (Dir, Shared(k)) => {
      if cek is Some(_) {
        raise Malformed("dir takes its key from the shared one")
      }
      if k.length() != enc.key_size() {
        raise Malformed("a shared key of the wrong length for " + enc.name())
      }
      k
    }
    (Dir, Rsa(_)) => raise Malformed("dir needs a shared key")
    (_, _) => {
      guard cek is Some(c) else {
        raise Malformed("a content key is needed under " + alg.name())
      }
      if c.length() != enc.key_size() {
        raise Malformed("a content key of the wrong length for " + enc.name())
      }
      c
    }
  }
  let wrapped = match alg {
    Dir => b""
    A128Kw | A192Kw | A256Kw => {
      guard key is Shared(k) else {
        raise Malformed(alg.name() + " needs a shared key")
      }
      match alg {
        A128Kw =>
          if k.length() != 16 {
            raise Malformed("an A128KW key is sixteen octets")
          }
        A192Kw =>
          if k.length() != 24 {
            raise Malformed("an A192KW key is twenty-four octets")
          }
        A256Kw =>
          if k.length() != 32 {
            raise Malformed("an A256KW key is thirty-two octets")
          }
        _ => ()
      }
      wrap(k[:], content_key[:])
    }
    RsaOaep256 => {
      guard key is Rsa(k) else {
        raise Malformed("RSA-OAEP-256 needs an RSA key")
      }
      if seed.length() == 0 {
        raise Malformed("RSA-OAEP-256 needs a seed for its padding")
      }
      k.encrypt(
        content_key[:],
        seed~,
        digest=@rsa.Sha256,
        mgf=@rsa.Sha256,
        label=b"",
      ) catch {
        _ => raise Malformed("the RSA key cannot encrypt under OAEP")
      }
    }
  }
  let head = Json::object({
    "alg": Json::string(alg.name()),
    "enc": Json::string(enc.name()),
  })
  let header = b64(@utf8.encode(@json.dumps(head)))
  let (cipher, tag) = content_seal(
    enc,
    content_key,
    iv,
    plain,
    @utf8.encode(header),
  )
  header +
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
/// Open a token, checking that the header names the algorithms the caller expects.
///
/// The expected `alg` and `enc` are arguments and not read from the header on the caller's behalf
/// for the reason JWT's `none` exists: a recipient that believes whatever the token says about
/// itself can be talked into the weakest algorithm it supports. A token that names another
/// algorithm is `Malformed` rather than opened under the caller's.
pub fn decrypt(
  text : StringView,
  key~ : Identity,
  alg~ : Alg,
  enc~ : Enc,
) -> Bytes raise Refused {
  let parts = split(text)
  let (head, wrapped, iv, cipher, tag) = match parts {
    [h, w, i, c, t] => (h, w, i, c, t)
    _ => raise Malformed("a compact JWE is five dot-separated parts")
  }
  let raw_header = b64_decode(head)
  let header_text = @utf8.decode(raw_header) catch {
    _ => raise Malformed("the header is not UTF-8")
  }
  let header = @json.loads(header_text) catch {
    _ => raise Malformed("the header is not JSON")
  }
  let named = match header {
    Object(fields) => {
      let a = match fields.get("alg") {
        Some(Json::String(s)) => s
        _ => raise Malformed("the header names no algorithm")
      }
      let e = match fields.get("enc") {
        Some(Json::String(s)) => s
        _ => raise Malformed("the header names no content encryption")
      }
      (a, e)
    }
    _ => raise Malformed("the header is not an object")
  }
  let (a, e) = named
  if alg_of(a) != alg {
    raise Malformed("the token is " + a + ", not " + alg.name())
  }
  if enc_of(e) != enc {
    raise Malformed("the token is " + e + ", not " + enc.name())
  }
  let content_key = match alg {
    Dir =>
      match key {
        Shared(k) =>
          if k.length() != enc.key_size() {
            raise Malformed(
              "a shared key of the wrong length for " + enc.name(),
            )
          } else {
            k
          }
        Rsa(_) => raise Malformed("dir needs a shared key")
      }
    A128Kw | A192Kw | A256Kw => {
      let kek = match key {
        Shared(k) => k
        Rsa(_) => raise Malformed(alg.name() + " needs a shared key")
      }
      let opened = unwrap(kek[:], b64_decode(wrapped)) catch { _ => raise Key }
      if opened.length() != enc.key_size() {
        raise Key
      }
      opened
    }
    RsaOaep256 => {
      let private_key = match key {
        Rsa(k) => k
        Shared(_) => raise Malformed("RSA-OAEP-256 needs an RSA key")
      }
      let opened = private_key.decrypt(
        b64_decode(wrapped),
        digest=@rsa.Sha256,
        mgf=@rsa.Sha256,
        label=b"",
      ) catch {
        _ => raise Key
      }
      if opened.length() != enc.key_size() {
        raise Key
      }
      opened
    }
  }
  content_open(
    enc,
    content_key,
    b64_decode(iv),
    b64_decode(cipher),
    b64_decode(tag),
    @utf8.encode(head),
  )
}

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
/// The inverse: `Malformed` when the tag does not match, which is how a wrong key and an edited
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

///|
/// base64url without padding, the only encoding the compact serialisation uses.
fn b64(bytes : Bytes) -> String {
  @base64.encode(bytes[:], kind=Url, padding=false)
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

///|
pub extend Alg with Eq::{equal, not_equal}

///|
pub extend Alg with Debug::{to_repr}

///|
pub extend Enc with Eq::{equal, not_equal}

///|
pub extend Enc with Debug::{to_repr}
