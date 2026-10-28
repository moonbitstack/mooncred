// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// An EncryptedPrivateKeyInfo (RFC 5958 §2) is the key file a passphrase protects: an algorithm
// identifier that says how the octets below were made unreadable, and the octets. Two families
// of algorithm reach this reader — PBES2, which pairs any cipher with a deliberately slow key
// derivation, and PBES1, which is one cipher bolted to one digest and exists because PKCS#12
// has files from 1999 that still open in a browser.
//
// Nothing here draws entropy. A salt and an initialisation vector come in from the caller,
// because a library that quietly seeds a generator is a library whose keys are as random as
// whatever it found to seed with.

///|
/// Why an encrypted key could not be read or written.
pub(all) suberror Refused {
  /// The bytes are not an EncryptedPrivateKeyInfo this package understands.
  Malformed(String)
  /// Well-formed, but an algorithm or parameter this package does not implement.
  Unsupported(String)
  /// The octets do not decrypt under this passphrase.
  Passphrase
} derive(Eq, Debug)

///|
/// The key derivation a file names, with what it needs to run.
pub(all) enum Kdf {
  /// PBKDF2 (RFC 8018 §5.2): the salt, the round count, the pseudorandom function, and the key
  /// length when the file pins one.
  Pbkdf2(salt~ : Bytes, rounds~ : Int32, prf~ : String, length~ : Int32?)
  /// The PKCS#12 derivation (RFC 7292 §B.2), which PBES1 under the PKCS#12 OIDs uses.
  Pkcs12(salt~ : Bytes, rounds~ : Int32)
  /// PBKDF1 (RFC 8018 §5.1), which the PKCS#5 PBES1 schemes use. `md5` is false for SHA-1.
  Pbkdf1(salt~ : Bytes, rounds~ : Int32, md5~ : Bool)
} derive(Eq, Debug)

///|
/// A parsed EncryptedPrivateKeyInfo. `body` is the ciphertext; everything else is what is needed
/// to turn it back into a PrivateKeyInfo.
pub(all) struct Encrypted {
  raw : Bytes
  /// The `encryptionAlgorithm` OID: PBES2, or one of the PBES1 schemes.
  alg : String
  kdf : Kdf
  /// The content-encryption OID, for PBES2 only.
  cipher : String?
  /// The initialisation vector or GCM nonce, for PBES2 only.
  iv : Bytes?
  /// The GCM tag length in octets; zero when the cipher is not GCM.
  icv : Int32
  body : Bytes
} derive(Eq, Debug)

///|
/// How to write an encrypted key. The first six are PBES2 with PBKDF2; the last two are the
/// PBES1 schemes a PKCS#12 file needs when it has to be readable by a client from before 2010.
pub(all) enum Scheme {
  Aes128Cbc
  Aes192Cbc
  Aes256Cbc
  Aes128Gcm
  Aes192Gcm
  Aes256Gcm
  /// PBES2 with three-key triple DES.
  TripleDesCbc
  /// PBES1 pbeWithSHAAnd3-KeyTripleDES-CBC, the PKCS#12 key bag encryption.
  LegacyTripleDes
  /// PBES1 pbeWithSHAAnd40BitRC2-CBC, the PKCS#12 certificate bag encryption.
  LegacyRc2
}

///|
/// PBES2 (RFC 8018 §6.2).
let pbES2 : String = "1.2.840.113549.1.5.13"

///|
/// PBKDF2 (RFC 8018 §5.2).
let pbkdf2_oid : String = "1.2.840.113549.1.5.12"

///|
/// pbeWithSHAAnd3-KeyTripleDES-CBC (RFC 7292 §B.1).
let pbe_3des : String = "1.2.840.113549.1.12.1.3"

///|
/// pbeWithSHAAnd2-KeyTripleDES-CBC.
let pbe_2des : String = "1.2.840.113549.1.12.1.4"

///|
/// pbeWithSHAAnd128BitRC2-CBC.
let pbe_rc2_128 : String = "1.2.840.113549.1.12.1.5"

///|
/// pbeWithSHAAnd40BitRC2-CBC.
let pbe_rc2_40 : String = "1.2.840.113549.1.12.1.6"

///|
/// pbeWithMD5AndDES-CBC (PKCS#5 v1.5).
let pbe_md5_des : String = "1.2.840.113549.1.5.3"

///|
/// pbeWithSHA1AndDES-CBC.
let pbe_sha1_des : String = "1.2.840.113549.1.5.10"

///|
/// The salt, round count and cipher of a PBES1 AlgorithmIdentifier (RFC 8018 §6.1).
fn pbes1_params(v : BytesView) -> (Bytes, Int32) raise Refused {
  let seq = @asn1.only(v) catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if seq.tag != 0x30 {
    raise Malformed("PBES1 parameters are not a SEQUENCE")
  }
  let items = seq.items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if items.length() != 2 {
    raise Malformed("PBES1 parameters are not a salt and a round count")
  }
  let salt = items[0].octets() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  let rounds = items[1].int() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if rounds < (1 : BigInt) || rounds > (10_000_000 : BigInt) {
    raise Malformed("PBES1 round count out of range")
  }
  if salt.length() == 0 {
    raise Malformed("PBES1 without a salt")
  }
  (salt.to_owned(), rounds.to_int())
}

///|
/// A PBKDF2-params (RFC 8018 §5.2), from its SEQUENCE.
fn pbkdf2_params(v : BytesView) -> Kdf raise Refused {
  let seq = @asn1.only(v) catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if seq.tag != 0x30 {
    raise Malformed("PBKDF2-params is not a SEQUENCE")
  }
  let items = seq.items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if items.length() == 0 || items.length() > 4 {
    raise Malformed("PBKDF2-params has the wrong number of fields")
  }
  if items[0].tag != 0x04 {
    raise Unsupported("PBKDF2 with a salt the key agreement supplies")
  }
  let salt = items[0].octets() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  let mut rounds = 0
  let mut length : Int32? = None
  let mut prf = "1.2.840.113549.2.7"
  for i = 1; i < items.length(); i = i + 1 {
    match items[i].tag {
      0x02 => {
        let n = items[i].int() catch {
          @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
        }
        if n < (1 : BigInt) || n > (100_000_000 : BigInt) {
          raise Malformed("PBKDF2 parameter out of range")
        }
        if length is None && rounds == 0 {
          rounds = n.to_int()
        } else {
          length = Some(n.to_int())
        }
      }
      0x30 => {
        let alg = items[i].items() catch {
          @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
        }
        if alg.length() == 0 {
          raise Malformed("PBKDF2 prf is not an algorithm identifier")
        }
        prf = alg[0].oid() catch {
          @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
        }
      }
      _ => raise Malformed("unexpected field in PBKDF2-params")
    }
  }
  if rounds == 0 {
    raise Malformed("PBKDF2 without a round count")
  }
  if salt.length() == 0 {
    raise Malformed("PBKDF2 without a salt")
  }
  Kdf::Pbkdf2(salt=salt.to_owned(), rounds~, prf~, length~)
}

///|
/// Read an EncryptedPrivateKeyInfo.
pub fn Encrypted::parse(der : BytesView) -> Encrypted raise Refused {
  let seq = @asn1.only(der) catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if seq.tag != 0x30 {
    raise Malformed("EncryptedPrivateKeyInfo is not a SEQUENCE")
  }
  let items = seq.items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if items.length() != 2 {
    raise Malformed(
      "EncryptedPrivateKeyInfo is not an algorithm and a ciphertext",
    )
  }
  if items[0].tag != 0x30 {
    raise Malformed("the encryption algorithm is not a SEQUENCE")
  }
  let alg = items[0].items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if alg.length() == 0 || alg.length() > 2 {
    raise Malformed("the encryption algorithm is not an OID and its parameters")
  }
  let oid = alg[0].oid() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  let params = if alg.length() == 2 { Some(alg[1].raw) } else { None }
  let body = items[1].octets() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  let raw = seq.raw.to_owned()
  if oid == pbES2 {
    guard params is Some(p) else { raise Malformed("PBES2 without parameters") }
    let (kdf, cipher, iv, icv) = pbes2_params(p)
    return {
      raw,
      alg: oid,
      kdf,
      cipher: Some(cipher),
      iv: Some(iv),
      icv,
      body: body.to_owned(),
    }
  }
  guard params is Some(p) else { raise Malformed("PBES1 without parameters") }
  let (salt, rounds) = pbes1_params(p)
  let kdf = match oid {
    a if a == pbe_md5_des => Kdf::Pbkdf1(salt~, rounds~, md5=true)
    a if a == pbe_sha1_des => Kdf::Pbkdf1(salt~, rounds~, md5=false)
    a if a == pbe_3des || a == pbe_2des || a == pbe_rc2_128 || a == pbe_rc2_40 =>
      Kdf::Pkcs12(salt~, rounds~)
    a => raise Unsupported("encryption algorithm " + a)
  }
  { raw, alg: oid, kdf, cipher: None, iv: None, icv: 0, body: body.to_owned(), }
}

///|
/// A PBES2-params (RFC 8018 §6.2), which is the KDF's identifier followed by the cipher's.
fn pbes2_params(v : BytesView) -> (Kdf, String, Bytes, Int32) raise Refused {
  let seq = @asn1.only(v) catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if seq.tag != 0x30 {
    raise Malformed("PBES2-params is not a SEQUENCE")
  }
  let items = seq.items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if items.length() != 2 {
    raise Malformed("PBES2-params is not a KDF and a cipher")
  }
  let kdf_seq = items[0].items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if kdf_seq.length() != 2 || kdf_seq[0].tag != 0x06 {
    raise Malformed("PBES2 key derivation is not an OID and its parameters")
  }
  let kdf_oid = kdf_seq[0].oid() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if kdf_oid != pbkdf2_oid {
    raise Unsupported("key derivation function " + kdf_oid)
  }
  let kdf = pbkdf2_params(kdf_seq[1].raw)
  let enc = items[1].items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if enc.length() == 0 || enc.length() > 2 || enc[0].tag != 0x06 {
    raise Malformed("PBES2 cipher is not an OID and its parameters")
  }
  let cipher = enc[0].oid() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if enc.length() != 2 {
    raise Malformed("PBES2 cipher " + cipher + " without parameters")
  }
  let (iv, icv) = match cipher {
    c if c == aes128_gcm || c == aes192_gcm || c == aes256_gcm =>
      gcm_params(enc[1])
    c if c == aes128_cbc || c == aes192_cbc || c == aes256_cbc || c == aaa_3des => {
      let iv = enc[1].octets() catch {
        @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
      }
      (iv.to_owned(), 0)
    }
    c => raise Unsupported("PBES2 cipher " + c)
  }
  (kdf, cipher, iv, icv)
}

///|
let aes128_cbc : String = "2.16.840.1.101.3.4.1.2"

///|
let aes192_cbc : String = "2.16.840.1.101.3.4.1.22"

///|
let aes256_cbc : String = "2.16.840.1.101.3.4.1.42"

///|
let aes128_gcm : String = "2.16.840.1.101.3.4.1.6"

///|
let aes192_gcm : String = "2.16.840.1.101.3.4.1.26"

///|
let aes256_gcm : String = "2.16.840.1.101.3.4.1.46"

///|
let aaa_3des : String = "1.2.840.113549.3.7"

///|
/// GCMParameters (RFC 5084 §3.2): the nonce, and the tag length which defaults to twelve.
fn gcm_params(t : @asn1.Tlv) -> (Bytes, Int32) raise Refused {
  if t.tag != 0x30 {
    raise Malformed("GCMParameters is not a SEQUENCE")
  }
  let items = t.items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if items.length() == 0 || items.length() > 2 {
    raise Malformed("GCMParameters is not a nonce and a tag length")
  }
  let nonce = items[0].octets() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  let mut icv = 12
  if items.length() == 2 {
    let n = items[1].int() catch {
      @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
    }
    if n < (12 : BigInt) || n > (16 : BigInt) {
      raise Malformed("a GCM tag length outside 12..16 octets")
    }
    icv = n.to_int()
  }
  (nonce.to_owned(), icv)
}

///|
/// What the file calls itself, for a log line or an error message.
pub fn Encrypted::name(self : Encrypted) -> String {
  match self.alg {
    a if a == pbES2 => "PBES2 " + cipher_name(self.cipher)
    a if a == pbe_3des => "pbeWithSHAAnd3-KeyTripleDES-CBC"
    a if a == pbe_2des => "pbeWithSHAAnd2-KeyTripleDES-CBC"
    a if a == pbe_rc2_128 => "pbeWithSHAAnd128BitRC2-CBC"
    a if a == pbe_rc2_40 => "pbeWithSHAAnd40BitRC2-CBC"
    a if a == pbe_md5_des => "pbeWithMD5AndDES-CBC"
    a if a == pbe_sha1_des => "pbeWithSHA1AndDES-CBC"
    a => a
  }
}

///|
fn cipher_name(cipher : String?) -> String {
  match cipher {
    Some(c) if c == aes128_cbc => "AES-128-CBC"
    Some(c) if c == aes192_cbc => "AES-192-CBC"
    Some(c) if c == aes256_cbc => "AES-256-CBC"
    Some(c) if c == aes128_gcm => "AES-128-GCM"
    Some(c) if c == aes192_gcm => "AES-192-GCM"
    Some(c) if c == aes256_gcm => "AES-256-GCM"
    Some(c) if c == aaa_3des => "triple DES-CBC"
    Some(c) => c
    None => "no cipher"
  }
}

///|
/// Recover the PrivateKeyInfo these octets hold.
pub fn Encrypted::decrypt(
  self : Encrypted,
  passphrase~ : StringView,
) -> Bytes raise Refused {
  let (key, iv) = self.keys(passphrase~)
  self.open(key, iv) catch {
    Passphrase => raise Passphrase
    e => raise e
  }
}

///|
/// The `encryptionAlgorithm` field of this file, as DER — the AlgorithmIdentifier a container
/// needs when it stores these octets somewhere other than an EncryptedPrivateKeyInfo, as a
/// PKCS#12 EncryptedData does.
pub fn Encrypted::algorithm(self : Encrypted) -> Bytes raise Refused {
  let seq = @asn1.only(self.raw) catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  let items = seq.items() catch {
    @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(m)
  }
  if items.length() != 2 {
    raise Malformed(
      "EncryptedPrivateKeyInfo is not an algorithm and a ciphertext",
    )
  }
  items[0].raw.to_owned()
}

///|
/// Decrypt `ciphertext` under an AlgorithmIdentifier that arrived on its own, outside an
/// EncryptedPrivateKeyInfo. A PKCS#12 EncryptedData carries its scheme this way, and so does a
/// CMS EnvelopedData; wrapping the two fields back into the file they would have been is what
/// lets one reader serve them all.
pub fn decrypt(
  alg : BytesView,
  ciphertext : BytesView,
  passphrase~ : StringView,
) -> Bytes raise Refused {
  let wrapped = @asn1.sequence([
    alg.to_owned(),
    @asn1.octet_string(ciphertext.to_owned()),
  ])
  Encrypted::parse(wrapped[:]).decrypt(passphrase~)
}

///|
/// The key and IV this file's parameters derive, before the cipher runs.
fn Encrypted::keys(
  self : Encrypted,
  passphrase~ : StringView,
) -> (Bytes, Bytes) raise Refused {
  match self.kdf {
    Pbkdf2(salt~, rounds~, prf~, length~) => {
      let kind = prf_of(prf)
      let cipher = self.cipher.unwrap_or("")
      let want = match length {
        Some(n) => n
        None => cipher_key_size(cipher)
      }
      if length is Some(n) && n != cipher_key_size(cipher) {
        raise Malformed("a PBKDF2 key length that is not the cipher's own")
      }
      let key = pbkdf2(@utf8.encode(passphrase)[:], salt[:], rounds, want, kind)
      (key, self.iv.unwrap_or(b""))
    }
    Pkcs12(salt~, rounds~) => {
      let (size, _) = pbes1_shape(self.alg)
      let key = pkcs12_key(passphrase, salt[:], id=1, rounds~, len=size)
      let iv = pkcs12_key(
        passphrase,
        salt[:],
        id=2,
        rounds~,
        len=block_of(self.alg),
      )
      (key, iv)
    }
    Pbkdf1(salt~, rounds~, md5~) => {
      let derived = pbkdf1(
        @utf8.encode(passphrase)[:],
        salt[:],
        rounds,
        16,
        md5~,
      )
      (derived[:8].to_owned(), derived[8:16].to_owned())
    }
  }
}

///|
fn cipher_key_size(cipher : String) -> Int32 raise Refused {
  match cipher {
    c if c == aes128_cbc || c == aes128_gcm => 16
    c if c == aes192_cbc || c == aes192_gcm => 24
    c if c == aes256_cbc || c == aes256_gcm => 32
    c if c == aaa_3des => 24
    c => raise Unsupported("cipher " + c)
  }
}

///|
/// The key length and effective key bits of a PBES1 scheme.
fn pbes1_shape(alg : String) -> (Int32, Int32) raise Refused {
  match alg {
    a if a == pbe_3des => (24, 0)
    a if a == pbe_2des => (16, 0)
    a if a == pbe_rc2_40 => (5, 40)
    a if a == pbe_rc2_128 => (16, 128)
    a if a == pbe_md5_des || a == pbe_sha1_des => (8, 0)
    a => raise Unsupported("encryption algorithm " + a)
  }
}

///|
fn block_of(alg : String) -> Int32 {
  match alg {
    a if a == pbe_3des || a == pbe_2des => 8
    a if a == pbe_rc2_40 || a == pbe_rc2_128 => 8
    a if a == pbe_md5_des || a == pbe_sha1_des => 8
    _ => 16
  }
}

///|
/// Run the cipher over the ciphertext with the derived key.
fn Encrypted::open(
  self : Encrypted,
  key : Bytes,
  iv : Bytes,
) -> Bytes raise Refused {
  match self.alg {
    a if a == pbES2 => {
      let cipher = self.cipher.unwrap_or("")
      match cipher {
        c if c == aes128_cbc || c == aes192_cbc || c == aes256_cbc =>
          cbc_decrypt(key[:], iv[:], self.body[:], 16, tdes=false)
        c if c == aaa_3des =>
          cbc_decrypt(key[:], iv[:], self.body[:], 8, tdes=true)
        c if c == aes128_gcm || c == aes192_gcm || c == aes256_gcm =>
          open_gcm(key[:], iv[:], self.body[:], self.icv)
        c => raise Unsupported("PBES2 cipher " + c)
      }
    }
    a if a == pbe_3des || a == pbe_2des =>
      cbc_decrypt(key[:], iv[:], self.body[:], 8, tdes=true)
    a if a == pbe_rc2_40 || a == pbe_rc2_128 => {
      let bits = if a == pbe_rc2_40 { 40 } else { 128 }
      rc2_cbc(key[:], iv[:], self.body[:], bits, decrypt=true)
    }
    a if a == pbe_md5_des || a == pbe_sha1_des =>
      cbc_decrypt(key[:], iv[:], self.body[:], 8, tdes=false)
    a => raise Unsupported("encryption algorithm " + a)
  }
}

///|
fn open_gcm(
  key : BytesView,
  nonce : BytesView,
  cipher : BytesView,
  icv : Int32,
) -> Bytes raise Refused {
  let block = @aes.Cipher::new(key) catch {
    _ => raise Malformed("an AES key of the wrong length")
  }
  let gcm = @gcm.Gcm::new(block, tag=icv) catch {
    _ => raise Malformed("a GCM tag length this cipher refuses")
  }
  gcm.open(nonce~, cipher~, aad=b"") catch {
    _ => raise Passphrase
  }
}

///|
fn seal_gcm(
  key : BytesView,
  nonce : BytesView,
  plain : BytesView,
  icv : Int32,
) -> Bytes raise Refused {
  let block = @aes.Cipher::new(key) catch {
    _ => raise Malformed("an AES key of the wrong length")
  }
  let gcm = @gcm.Gcm::new(block, tag=icv) catch {
    _ => raise Malformed("a GCM tag length this cipher refuses")
  }
  gcm.seal(nonce~, plain~, aad=b"")
}

///|
/// RC2 in CBC mode with PKCS#7 padding, the form a PKCS#12 certificate bag uses.
fn rc2_cbc(
  key : BytesView,
  iv : BytesView,
  input : BytesView,
  bits : Int32,
  decrypt~ : Bool,
) -> Bytes raise Refused {
  if decrypt {
    if input.length() == 0 || input.length() % 8 != 0 {
      raise Malformed("an RC2 ciphertext that is not whole blocks")
    }
    let out = Buffer()
    let mut chain = iv.to_owned()
    let mut off = 0
    while off < input.length() {
      let block = input[off:off + 8]
      let opened = rc2_block(key, bits, block, decrypt=true)
      for i in 0..<8 {
        out.write_byte((opened[i].to_int() ^ chain[i].to_int()).to_byte())
      }
      chain = block.to_owned()
      off = off + 8
    }
    let padded = out.to_bytes()
    let pad = padded[padded.length() - 1].to_int()
    if pad < 1 || pad > 8 {
      raise Passphrase
    }
    for i in 1..<=pad {
      if padded[padded.length() - i].to_int() != pad {
        raise Passphrase
      }
    }
    padded[:padded.length() - pad].to_owned()
  } else {
    let pad = 8 - input.length() % 8
    let body = Buffer()
    body.write_bytesview(input)
    for _ in 0..<pad {
      body.write_byte(pad.to_byte())
    }
    let padded = body.to_bytes()
    let out = Buffer()
    let mut chain = iv.to_owned()
    let mut off = 0
    while off < padded.length() {
      let block = Buffer()
      for i in 0..<8 {
        block.write_byte(
          (padded[off + i].to_int() ^ chain[i].to_int()).to_byte(),
        )
      }
      let out_block = rc2_block(key, bits, block.to_bytes()[:], decrypt=false)
      out.write_bytes(out_block[:])
      chain = out_block
      off = off + 8
    }
    out.to_bytes()
  }
}

///|
/// Encrypt a PrivateKeyInfo under a passphrase.
///
/// `salt` and `iv` are the caller's: a salt must be new for every key ever written, and this
/// library has no generator to draw one from. Sixteen octets of salt is what PBKDF2 is usually
/// given; the IV must be the cipher's block size — sixteen for AES, eight for triple DES, and
/// twelve for a GCM nonce.
pub fn encrypt(
  plain : BytesView,
  passphrase~ : StringView,
  salt~ : BytesView,
  iv~ : BytesView,
  scheme~ : Scheme = Aes256Cbc,
  rounds~ : Int32 = 100_000,
) -> Bytes raise Refused {
  match scheme {
    LegacyTripleDes | LegacyRc2 => {
      if rounds < 1 {
        raise Malformed("a round count below one")
      }
      let alg = if scheme is LegacyTripleDes { pbe_3des } else { pbe_rc2_40 }
      let (size, bits) = pbes1_shape(alg)
      let key = pkcs12_key(passphrase, salt, id=1, rounds~, len=size)
      let actual = pkcs12_key(passphrase, salt, id=2, rounds~, len=8)
      let body = if scheme is LegacyTripleDes {
        cbc_encrypt(key[:], actual[:], plain, 8, tdes=true)
      } else {
        rc2_cbc(key[:], actual[:], plain, bits, decrypt=false)
      }
      let params = @asn1.sequence([
        @asn1.octet_string(salt.to_owned()),
        @asn1.integer(magnitude(rounds)),
      ])
      return @asn1.sequence([
        @asn1.sequence([oid_der(alg), params]),
        @asn1.octet_string(body),
      ])
    }
    _ => ()
  }
  let cipher = match scheme {
    Aes128Cbc => aes128_cbc
    Aes192Cbc => aes192_cbc
    Aes256Cbc => aes256_cbc
    Aes128Gcm => aes128_gcm
    Aes192Gcm => aes192_gcm
    Aes256Gcm => aes256_gcm
    TripleDesCbc => aaa_3des
    _ => raise Unsupported("scheme")
  }
  let size = cipher_key_size(cipher)
  let kind = Prf::Sha256
  let key = pbkdf2(@utf8.encode(passphrase)[:], salt, rounds, size, kind)
  let body = match scheme {
    TripleDesCbc => cbc_encrypt(key[:], iv, plain, 8, tdes=true)
    Aes128Gcm | Aes192Gcm | Aes256Gcm => seal_gcm(key[:], iv, plain, 16)
    _ => cbc_encrypt(key[:], iv, plain, 16, tdes=false)
  }
  let cipher_params = match scheme {
    Aes128Gcm | Aes192Gcm | Aes256Gcm =>
      @asn1.sequence([
        @asn1.octet_string(iv.to_owned()),
        @asn1.integer(magnitude(16)),
      ])
    _ => @asn1.octet_string(iv.to_owned())
  }
  let kdf_params = @asn1.sequence([
    @asn1.octet_string(salt.to_owned()),
    @asn1.integer(magnitude(rounds)),
    @asn1.sequence([oid_der(prf_oid(kind))]),
  ])
  let params = @asn1.sequence([
    @asn1.sequence([oid_der(pbkdf2_oid), kdf_params]),
    @asn1.sequence([oid_der(cipher), cipher_params]),
  ])
  @asn1.sequence([
    @asn1.sequence([oid_der(pbES2), params]),
    @asn1.octet_string(body),
  ])
}

///|
/// The DER of an OBJECT IDENTIFIER written in dotted-decimal form.
fn oid_der(dotted : String) -> Bytes raise Refused {
  let arcs : Array[Int32] = []
  let mut value = 0
  let mut digits = 0
  for c in dotted {
    match c {
      '0'..<='9' => {
        value = value * 10 + (c.to_int() - '0'.to_int())
        digits = digits + 1
        if value > 2_000_000_000 {
          raise Malformed("OID arc over 32 bits")
        }
      }
      '.' => {
        if digits == 0 {
          raise Malformed("OID has an empty arc")
        }
        arcs.push(value)
        value = 0
        digits = 0
      }
      _ => raise Malformed("OID has a character that is not a digit")
    }
  }
  if digits == 0 {
    raise Malformed("OID has an empty arc")
  }
  arcs.push(value)
  if arcs.length() < 2 {
    raise Malformed("OID has fewer than two arcs")
  }
  @asn1.oid(arcs)
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
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Kdf with Eq::{equal, not_equal}

///|
pub extend Kdf with Debug::{to_repr}

///|
pub extend Encrypted with Eq::{equal, not_equal}

///|
pub extend Encrypted with Debug::{to_repr}
