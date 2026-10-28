// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A PKCS#12 file is a PFX: a version, an AuthenticatedSafe wrapped in one ContentInfo, and a
// digest of that AuthenticatedSafe salted and stretched by the passphrase. Inside, the
// AuthenticatedSafe is a run of ContentInfos — some plain, some encrypted — each holding a
// SafeContents, which is a run of SafeBags: a key, a shrouded key, or a certificate.
//
// The layers exist because each one was added by a different committee, and none of them can be
// skipped: the digest covers the AuthenticatedSafe as it travels, not the bags it decrypts to, so
// it is the only thing that says the file was not edited between the two ends.

///|
/// Why a container could not be read or written: the octets are not a PFX, a scheme or a bag type
/// is not one this package implements, or the passphrase is not the file's.
pub(all) suberror Refused {
  Malformed(String)
  Unsupported(String)
  Passphrase
}

///|
/// The MAC a PFX carries (RFC 7292 §4): the digest algorithm, the digest, the salt it was
/// stretched with, and the round count. OpenSSL 3 writes SHA-256 where the 1999 files had SHA-1.
pub(all) struct Mac {
  alg : String
  digest : Bytes
  salt : Bytes
  iterations : Int32
}

///|
/// A parsed PFX. `auth_safe` is the AuthenticatedSafe octets the MAC covers, kept as a view for
/// the reason every signature in this library is checked over what arrived: re-encoding before
/// verifying would check a file that nobody sent.
pub(all) struct Pfx {
  raw : BytesView
  version : Int32
  auth_safe : BytesView
  mac : Mac?
}

///|
/// What a container held once it was opened: the certificates in the order the bags carried them,
/// and the private key as a PKCS#8 PrivateKeyInfo.
pub(all) struct Contents {
  certs : Array[Bytes]
  key : Bytes?
}

///|
/// id-data.
let oid_data : Array[Int32] = [1, 2, 840, 113549, 1, 7, 1]

///|
/// id-encryptedData.
let oid_encrypted_data : Array[Int32] = [1, 2, 840, 113549, 1, 7, 6]

///|
/// id-keyBag, a PrivateKeyInfo in the clear.
let oid_key_bag : Array[Int32] = [1, 2, 840, 113549, 1, 12, 10, 1, 1]

///|
/// id-pkcs8ShroudedKeyBag, an EncryptedPrivateKeyInfo.
let oid_shrouded_key_bag : Array[Int32] = [1, 2, 840, 113549, 1, 12, 10, 1, 2]

///|
/// id-certBag.
let oid_cert_bag : Array[Int32] = [1, 2, 840, 113549, 1, 12, 10, 1, 3]

///|
/// id-x509Certificate, the only certificate kind this package reads or writes.
let oid_x509_certificate : Array[Int32] = [1, 2, 840, 113549, 1, 9, 22, 1]

///|
/// sha256, the digest OpenSSL 3 puts on a MAC.
let oid_sha256 : Array[Int32] = [2, 16, 840, 1, 101, 3, 4, 2, 1]

///|
/// A dotted-decimal rendering of an OID given as its arcs, for comparing against the strings the
/// ASN.1 reader hands back. Written from the same constant the encoder uses, so the two cannot
/// drift apart.
fn dotted(arcs : Array[Int32]) -> String {
  let out = StringBuilder()
  let mut i = 0
  while i < arcs.length() {
    if i > 0 {
      out.write_char('.')
    }
    out.write_string(arcs[i].to_string())
    i = i + 1
  }
  out.to_string()
}

///|
/// The ASN.1 reader's errors, restated in this package's: a container that is not what it claims
/// and a container that will not open are the same two failures as everywhere else in the
/// credential stack, and a caller should not have to catch three error types to read one file.
fn only(der : BytesView) -> @asn1.Tlv raise Refused {
  let out = @asn1.only(der) catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  out
}

///|
fn fields(t : @asn1.Tlv) -> Array[@asn1.Tlv] raise Refused {
  t.items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
}

///|
fn integer(t : @asn1.Tlv) -> BigInt raise Refused {
  let out = t.int() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  out
}

///|
fn octets(t : @asn1.Tlv) -> BytesView raise Refused {
  let out = t.octets() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  out
}

///|
fn oid_of(t : @asn1.Tlv) -> String raise Refused {
  let out = t.oid() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  out
}

///|
/// Parse a PFX. Only the envelope is read here: the bags need the passphrase, so `contents` is
/// the call that opens them, and `verify` is the one that says whether the file was edited.
pub fn parse(der : BytesView) -> Pfx raise Refused {
  let top = only(der)
  if top.tag != 0x30 {
    raise Malformed("PFX is not a SEQUENCE")
  }
  let items = fields(top)
  if items.length() < 2 || items.length() > 3 {
    raise Malformed("PFX is not a version, an authSafe and a MAC")
  }
  let version = integer(items[0]).to_int()
  if version != 3 {
    raise Malformed("PFX version is not v3")
  }
  let (kind, body) = content_info(items[1])
  if kind != dotted(oid_data) {
    raise Malformed("PFX authSafe is not id-data")
  }
  let inner = only(body)
  if inner.tag != 0x04 {
    raise Malformed("PFX authSafe is not an OCTET STRING")
  }
  let mac = if items.length() == 3 { Some(read_mac(items[2])) } else { None }
  { raw: top.raw, version, auth_safe: octets(inner).to_owned(), mac, }
}

///|
/// The type and the inner octets of a ContentInfo (RFC 5652 §3): an OID and a `[0] EXPLICIT`
/// holding the value.
fn content_info(t : @asn1.Tlv) -> (String, BytesView) raise Refused {
  if t.tag != 0x30 {
    raise Malformed("ContentInfo is not a SEQUENCE")
  }
  let items = fields(t)
  if items.length() != 2 || items[0].tag != 0x06 || items[1].tag != 0xa0 {
    raise Malformed("ContentInfo is not an OID and a [0]")
  }
  (oid_of(items[0]), items[1].value)
}

///|
fn read_mac(t : @asn1.Tlv) -> Mac raise Refused {
  if t.tag != 0x30 {
    raise Malformed("MacData is not a SEQUENCE")
  }
  let items = fields(t)
  if items.length() < 2 || items.length() > 3 {
    raise Malformed("MacData is not a digest, a salt and a round count")
  }
  let info = fields(items[0])
  if info.length() != 2 {
    raise Malformed("DigestInfo is not an algorithm and a digest")
  }
  let alg = algorithm_oid(info[0])
  let digest = octets(info[1])
  let salt = octets(items[1])
  let mut iterations = 1
  if items.length() == 3 {
    let n = integer(items[2])
    if n < (1 : BigInt) || n > (10_000_000 : BigInt) {
      raise Malformed("MacData round count out of range")
    }
    iterations = n.to_int()
  }
  { alg, digest: digest.to_owned(), salt: salt.to_owned(), iterations, }
}

///|
/// The OID of an AlgorithmIdentifier.
fn algorithm_oid(t : @asn1.Tlv) -> String raise Refused {
  if t.tag != 0x30 {
    raise Malformed("AlgorithmIdentifier is not a SEQUENCE")
  }
  let items = fields(t)
  if items.length() == 0 || items.length() > 2 {
    raise Malformed("AlgorithmIdentifier is not an OID and its parameters")
  }
  oid_of(items[0])
}

///|
/// Whether the file carries a MAC at all. A PFX without one is not tampered with by definition —
/// there is nothing to check it against — but it is also not authenticated, and a caller that
/// needs that distinction can only make it if it is told.
pub fn Pfx::has_mac(self : Pfx) -> Bool {
  self.mac is Some(_)
}

///|
/// Whether the MAC this file carries is the one its passphrase produces over its AuthenticatedSafe.
///
/// False for a file with no MAC: nothing was verified, which is not the same as verified good.
/// The comparison is over the whole digest and does not stop at the first octet that differs, so
/// the answer leaks nothing about how close a guess was.
pub fn Pfx::verify(self : Pfx, passphrase~ : StringView) -> Bool raise Refused {
  guard self.mac is Some(m) else { return false }
  let (prf, size) = digest_of(m.alg)
  let key = @pbe.pkcs12_key_with(
    prf~,
    passphrase,
    m.salt[:],
    id=3,
    rounds=m.iterations,
    len=size,
  ) catch {
    @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
    @pbe.Passphrase => raise Passphrase
  }
  let got = @hmac.mac(key[:], self.auth_safe, () => hasher(prf))
  same(got, m.digest)
}

///|
/// The digest a MAC names, and the key length the PKCS#12 derivation is asked for: the digest's
/// own output length.
fn digest_of(oid : String) -> (Prf, Int32) raise Refused {
  match oid {
    "1.3.14.3.2.26" => (Sha1, 20)
    "2.16.840.1.101.3.4.2.1" => (Sha256, 32)
    "2.16.840.1.101.3.4.2.2" => (Sha384, 48)
    "2.16.840.1.101.3.4.2.3" => (Sha512, 64)
    _ => raise Unsupported("MAC digest " + oid)
  }
}

///|
fn hasher(prf : Prf) -> &@spec.Hash {
  match prf {
    Sha1 => (@sha1.Hasher::new() : &@spec.Hash)
    Sha224 => (@sha2.Hasher::new(kind=Sha224) : &@spec.Hash)
    Sha256 => (@sha2.Hasher::new(kind=Sha256) : &@spec.Hash)
    Sha384 => (@sha2.Hasher::new(kind=Sha384) : &@spec.Hash)
    Sha512 => (@sha2.Hasher::new(kind=Sha512) : &@spec.Hash)
  }
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
/// Open the container: the certificates every bag carried, and the private key with its shrouding
/// removed. The MAC is not checked here — `verify` is — because a caller may legitimately want to
/// look inside a file it cannot authenticate, and a library that refuses to say what is in a file
/// until it likes the file is a library that cannot be used to find out why.
pub fn Pfx::contents(
  self : Pfx,
  passphrase~ : StringView,
) -> Contents raise Refused {
  let seq = only(self.auth_safe)
  if seq.tag != 0x30 {
    raise Malformed("AuthenticatedSafe is not a SEQUENCE")
  }
  let certs : Array[Bytes] = []
  let mut key : Bytes? = None
  for info in fields(seq) {
    let (kind, body) = content_info(info)
    let plain = if kind == dotted(oid_data) {
      let inner = only(body)
      if inner.tag != 0x04 {
        raise Malformed("a plain SafeContents is not an OCTET STRING")
      }
      octets(inner)
    } else if kind == dotted(oid_encrypted_data) {
      open_encrypted_data(body, passphrase~)
    } else {
      raise Unsupported("AuthenticatedSafe content type " + kind)
    }
    let (found, one) = read_safe_contents(plain, passphrase~)
    for c in found {
      certs.push(c)
    }
    if key is None {
      key = one
    }
  }
  { certs, key, }
}

///|
/// The plaintext of an EncryptedData (RFC 5652 §8): the version, the EncryptedContentInfo with its
/// scheme and ciphertext, and nothing else — an unprotected attribute would be outside the MAC and
/// so outside what this parser is willing to read.
fn open_encrypted_data(
  v : BytesView,
  passphrase~ : StringView,
) -> Bytes raise Refused {
  let seq = only(v)
  if seq.tag != 0x30 {
    raise Malformed("EncryptedData is not a SEQUENCE")
  }
  let items = fields(seq)
  if items.length() != 2 {
    raise Malformed("EncryptedData is not a version and its content")
  }
  if integer(items[0]) != 0 {
    raise Malformed("EncryptedData version is not 0")
  }
  let info = fields(items[1])
  if info.length() != 3 || info[0].tag != 0x06 || info[2].tag != 0x80 {
    raise Malformed(
      "EncryptedContentInfo is not a type, an algorithm and a ciphertext",
    )
  }
  if oid_of(info[0]) != dotted(oid_data) {
    raise Unsupported("encrypted content of type " + oid_of(info[0]))
  }
  let plain = @pbe.decrypt(info[1].raw, info[2].value, passphrase~) catch {
    @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
    @pbe.Passphrase => raise Passphrase
  }
  plain
}

///|
/// The bags in a SafeContents, split into certificates and the first private key.
fn read_safe_contents(
  plain : BytesView,
  passphrase~ : StringView,
) -> (Array[Bytes], Bytes?) raise Refused {
  let seq = only(plain)
  if seq.tag != 0x30 {
    raise Malformed("SafeContents is not a SEQUENCE")
  }
  let certs : Array[Bytes] = []
  let mut key : Bytes? = None
  for bag in fields(seq) {
    if bag.tag != 0x30 {
      raise Malformed("SafeBag is not a SEQUENCE")
    }
    let parts = fields(bag)
    if parts.length() < 2 || parts[0].tag != 0x06 || parts[1].tag != 0xa0 {
      raise Malformed("SafeBag is not a type and a [0] value")
    }
    let id = oid_of(parts[0])
    let value = parts[1].value
    if id == dotted(oid_key_bag) {
      if key is None {
        key = Some(only(value).raw.to_owned())
      }
    } else if id == dotted(oid_shrouded_key_bag) {
      let plain_key = @pbe.Encrypted::parse(value).decrypt(passphrase~) catch {
        @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
        @pbe.Passphrase => raise Passphrase
      }
      if key is None {
        key = Some(plain_key)
      }
    } else if id == dotted(oid_cert_bag) {
      certs.push(read_cert_bag(value))
    } else {
      raise Unsupported("SafeBag of type " + id)
    }
  }
  (certs, key)
}

///|
/// A CertBag's certificate octets (RFC 7292 §4.2.2): id-x509Certificate, and the DER inside an
/// OCTET STRING inside the `[0]`.
fn read_cert_bag(v : BytesView) -> Bytes raise Refused {
  let seq = only(v)
  if seq.tag != 0x30 {
    raise Malformed("CertBag is not a SEQUENCE")
  }
  let parts = fields(seq)
  if parts.length() != 2 || parts[0].tag != 0x06 || parts[1].tag != 0xa0 {
    raise Malformed("CertBag is not a type and a [0] value")
  }
  if oid_of(parts[0]) != dotted(oid_x509_certificate) {
    raise Unsupported("CertBag of type " + oid_of(parts[0]))
  }
  let inner = only(parts[1].value)
  if inner.tag != 0x04 {
    raise Malformed("CertBag value is not an OCTET STRING")
  }
  octets(inner).to_owned()
}

///|
/// A non-negative integer as the magnitude an INTEGER is built from.
fn magnitude(n : Int32) -> Bytes {
  let digits : Array[Byte] = []
  let mut m = n
  if m == 0 {
    digits.push(b'\x00')
  }
  while m > 0 {
    digits.push((m % 256).to_byte())
    m = m / 256
  }
  let out = Buffer()
  for i in 0..<digits.length() {
    out.write_byte(digits[digits.length() - 1 - i])
  }
  out.to_bytes()
}

///|
/// Write a container holding `certs` and, when there is one, `key` — a PKCS#8 PrivateKeyInfo.
///
/// The certificates go into an EncryptedData under `scheme` and the key into a shrouded key bag
/// under the same one, which is the shape OpenSSL writes and the shape every client since 1999
/// knows how to open. `salt` and `iv` are the caller's for the reason this library has no
/// generator; the same pair encrypts both bags, so they must be fresh for every file, and the MAC
/// has a salt of its own because it is the one value a reader can check without a plaintext.
pub fn build(
  certs~ : ArrayView[Bytes],
  key~ : Bytes?,
  passphrase~ : StringView,
  salt~ : BytesView,
  iv~ : BytesView,
  mac_salt~ : BytesView,
  scheme~ : @pbe.Scheme = Aes256Cbc,
  rounds~ : Int32 = 10_000,
  mac_rounds~ : Int32 = 10_000,
) -> Bytes raise Refused {
  let bags = Buffer()
  for c in certs {
    bags.write_bytes(
      @asn1.sequence([
        @asn1.oid(oid_cert_bag),
        @asn1.explicit(
          0,
          @asn1.sequence([
            @asn1.oid(oid_x509_certificate),
            @asn1.explicit(0, @asn1.octet_string(c)),
          ]),
        ),
      ])[:],
    )
  }
  let cert_plain = @asn1.sequence([bags.to_bytes()])
  let cert_sealed = @pbe.encrypt(
    cert_plain[:],
    passphrase~,
    salt~,
    iv~,
    scheme~,
    rounds~,
  ) catch {
    @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
    @pbe.Passphrase => raise Passphrase
  }
  let opened = @pbe.Encrypted::parse(cert_sealed[:]) catch {
    @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
    @pbe.Passphrase => raise Passphrase
  }
  let scheme_der = opened.algorithm() catch {
    @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
    @pbe.Passphrase => raise Passphrase
  }
  let parts : Array[Bytes] = [
    content_info_der(
      oid_encrypted_data,
      @asn1.sequence([
        @asn1.integer(b"\x00"),
        @asn1.sequence([
          @asn1.oid(oid_data),
          scheme_der,
          @asn1.tlv(0x80, opened.body),
        ]),
      ]),
    ),
  ]
  match key {
    Some(k) => {
      let shrouded = @pbe.encrypt(
        k[:],
        passphrase~,
        salt~,
        iv~,
        scheme~,
        rounds~,
      ) catch {
        @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
        @pbe.Passphrase => raise Passphrase
      }
      let contents = @asn1.sequence([
        @asn1.sequence([
          @asn1.oid(oid_shrouded_key_bag),
          @asn1.explicit(0, shrouded),
        ]),
      ])
      parts.push(content_info_der(oid_data, @asn1.octet_string(contents)))
    }
    None => ()
  }
  let auth_safe = @asn1.sequence(parts)
  let mac_key = @pbe.pkcs12_key_with(
    prf=Sha256,
    passphrase,
    mac_salt,
    id=3,
    rounds=mac_rounds,
    len=32,
  ) catch {
    @pbe.Malformed(m) | @pbe.Unsupported(m) => raise Malformed(m)
    @pbe.Passphrase => raise Passphrase
  }
  let digest = @hmac.mac(mac_key[:], auth_safe[:], () => hasher(Sha256))
  let mac = @asn1.sequence([
    @asn1.sequence([
      @asn1.sequence([@asn1.oid(oid_sha256), @asn1.null()]),
      @asn1.octet_string(digest),
    ]),
    @asn1.octet_string(mac_salt.to_owned()),
    @asn1.integer(magnitude(mac_rounds)),
  ])
  @asn1.sequence([
    @asn1.integer(b"\x03"),
    content_info_der(oid_data, @asn1.octet_string(auth_safe)),
    mac,
  ])
}

///|
/// A ContentInfo with its `[0] EXPLICIT` already wrapped around `body`.
fn content_info_der(arcs : Array[Int32], body : Bytes) -> Bytes {
  @asn1.sequence([@asn1.oid(arcs), @asn1.explicit(0, body)])
}

///|
pub using @pbe {type Prf, type Scheme}
