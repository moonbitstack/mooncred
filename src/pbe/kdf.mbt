// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The key derivation functions under the schemes: PBKDF2 and PBKDF1 from PKCS#5, and PKCS#12's
// own, which differs from both in taking the passphrase as a BMPString and in mixing the salt
// and the passphrase into one buffer before hashing it.

///|
/// The pseudorandom function PBKDF2 is keyed with (RFC 8018 §5.2).
pub(all) enum Prf {
  Sha1
  Sha224
  Sha256
  Sha384
  Sha512
}

///|
/// The `prf` OID of a PBKDF2-params (RFC 8018 §A.2), hmacWithSHA1 being the default.
fn prf_of(oid : String) -> Prf raise Refused {
  match oid {
    "1.2.840.113549.2.7" => Sha1
    "1.2.840.113549.2.8" => Sha224
    "1.2.840.113549.2.9" => Sha256
    "1.2.840.113549.2.10" => Sha384
    "1.2.840.113549.2.11" => Sha512
    _ => raise Unsupported("PBKDF2 pseudorandom function " + oid)
  }
}

///|
fn prf_oid(prf : Prf) -> String {
  match prf {
    Sha1 => "1.2.840.113549.2.7"
    Sha224 => "1.2.840.113549.2.8"
    Sha256 => "1.2.840.113549.2.9"
    Sha384 => "1.2.840.113549.2.10"
    Sha512 => "1.2.840.113549.2.11"
  }
}

///|
fn make(prf : Prf) -> &@spec.Hash {
  match prf {
    Sha1 => (@sha1.Hasher::new() : &@spec.Hash)
    Sha224 => (@sha2.Hasher::new(kind=Sha224) : &@spec.Hash)
    Sha256 => (@sha2.Hasher::new(kind=Sha256) : &@spec.Hash)
    Sha384 => (@sha2.Hasher::new(kind=Sha384) : &@spec.Hash)
    Sha512 => (@sha2.Hasher::new(kind=Sha512) : &@spec.Hash)
  }
}

///|
/// PBKDF2 (RFC 8018 §5.2): the passphrase's own octets, the salt, and the number of rounds.
fn pbkdf2(
  passphrase : BytesView,
  salt : BytesView,
  rounds : Int32,
  len : Int32,
  prf : Prf,
) -> Bytes raise Refused {
  if rounds < 1 {
    raise Malformed("a PBKDF2 round count below one")
  }
  if len < 1 {
    raise Malformed("a PBKDF2 key length below one")
  }
  @pbkdf2.key(passphrase, salt, () => make(prf), rounds~, len~)
}

///|
/// PBKDF1 (RFC 8018 §5.1), which PBES1 uses: T1 = H(passphrase || salt), Tn = H(Tn-1), and the
/// key is Tc cut to length. It cannot make a key longer than the digest, and every PBES1
/// definition asks for exactly one digest's worth.
fn pbkdf1(
  passphrase : BytesView,
  salt : BytesView,
  rounds : Int32,
  len : Int32,
  md5~ : Bool,
) -> Bytes raise Refused {
  if rounds < 1 {
    raise Malformed("a PBKDF1 round count below one")
  }
  let h : &@spec.Hash = if md5 {
    (@md5.Hasher::new() : &@spec.Hash)
  } else {
    (@sha1.Hasher::new() : &@spec.Hash)
  }
  h.write(passphrase)
  h.write(salt)
  let mut answer = h.finish()
  if len > answer.length() {
    raise Unsupported("a PBES1 key longer than its digest")
  }
  for _ in 1..<rounds {
    h.reset()
    h.write(answer[:])
    answer = h.finish()
  }
  answer[:len].to_owned()
}

///|
/// A passphrase as the BMPString PKCS#12 hashes: UTF-16 big-endian, closed by two zero octets
/// (RFC 7292 §B.1).
fn bmp(password : StringView) -> Bytes {
  let out = Buffer()
  for c in password {
    let unit = c.to_int()
    if unit <= 0xffff {
      out.write_byte((unit >> 8).to_byte())
      out.write_byte((unit & 0xff).to_byte())
    } else {
      let low = unit - 0x10000
      let high = 0xd800 + (low >> 10)
      let tail = 0xdc00 + (low & 0x3ff)
      out.write_byte((high >> 8).to_byte())
      out.write_byte((high & 0xff).to_byte())
      out.write_byte((tail >> 8).to_byte())
      out.write_byte((tail & 0xff).to_byte())
    }
  }
  out.write_byte(b'\x00')
  out.write_byte(b'\x00')
  out.to_bytes()
}

///|
/// `source` repeated up to the next multiple of `width` and cut there — how the PKCS#12 KDF
/// fills its salt and passphrase buffers. An empty source stays empty.
fn fill(source : BytesView, width : Int32) -> Bytes {
  if source.length() == 0 {
    return b""
  }
  let want = (source.length() + width - 1) / width * width
  let out = Buffer()
  while out.length() < want {
    out.write_bytesview(source)
  }
  let all = out.to_bytes()
  all[:want].to_owned()
}

///|
/// `source` repeated and cut to exactly `width`.
fn stretch(source : BytesView, width : Int32) -> Bytes {
  let out = Buffer()
  while out.length() < width {
    out.write_bytesview(source)
  }
  let all = out.to_bytes()
  all[:width].to_owned()
}

///|
/// I = (I + B + 1) mod 2^(v*8), over each `v`-octet block in turn (RFC 7292 §B.2 step 6.b).
fn add_blocks(i : Bytes, b : BytesView, width : Int32) -> Bytes {
  let out = Buffer()
  let mut block = 0
  while block < i.length() {
    // The sums go in unmasked so that the carry out of one octet reaches the next; only the
    // final carry past the top octet is dropped, which is the mod 2^(v*8) in the definition.
    let digits = FixedArray::make(width, 0)
    for k in 0..<width {
      digits[k] = i[block + k].to_int() + b[k].to_int()
    }
    let mut carry = 1
    let mut k = width - 1
    while k >= 0 {
      let sum = digits[k] + carry
      digits[k] = sum & 0xff
      carry = sum >> 8
      k = k - 1
    }
    for k in 0..<width {
      out.write_byte(digits[k].to_byte())
    }
    block = block + width
  }
  out.to_bytes()
}

///|
/// The PKCS#12 key derivation (RFC 7292 §B.2). `id` says what the key is for: 1 an encryption
/// key, 2 an IV, 3 a MAC key.
///
/// The hash is a parameter here because a PKCS#12 file's MAC names its own digest — OpenSSL 3
/// writes SHA-256 where the 1999 files had SHA-1 — and the width the derivation mixes in is that
/// hash's block size, not its output length.
pub fn pkcs12_key_with(
  prf~ : Prf,
  passphrase : StringView,
  salt : BytesView,
  id~ : Int32,
  rounds~ : Int32,
  len~ : Int32,
) -> Bytes raise Refused {
  if rounds < 1 {
    raise Malformed("a PKCS#12 round count below one")
  }
  let width = block_width(prf)
  let repeated = Buffer()
  for _ in 0..<width {
    repeated.write_byte(id.to_byte())
  }
  let d = repeated.to_bytes()
  let s = fill(salt, width)
  let p = fill(bmp(passphrase)[:], width)
  let seed = Buffer()
  seed.write_bytes(s[:])
  seed.write_bytes(p[:])
  let mut i = seed.to_bytes()
  let out = Buffer()
  while out.length() < len {
    let h = make(prf)
    h.write(d[:])
    h.write(i[:])
    let mut a = h.finish()
    for _ in 1..<rounds {
      a = one_shot(prf, a[:])
    }
    out.write_bytes(a[:])
    let b = stretch(a[:], width)
    i = add_blocks(i, b[:], width)
  }
  let all = out.to_bytes()
  all[:len].to_owned()
}

///|
/// One hash of `data` under `prf`, for the rounds after the first.
fn one_shot(prf : Prf, data : BytesView) -> Bytes {
  let h = make(prf)
  h.write(data)
  h.finish()
}

///|
/// The width the PKCS#12 derivation repeats into: the hash's block size, which is 64 for SHA-1,
/// SHA-224 and SHA-256 and 128 for SHA-384 and SHA-512.
fn block_width(prf : Prf) -> Int32 {
  match prf {
    Sha384 | Sha512 => 128
    _ => 64
  }
}

///|
/// The same derivation with SHA-1, which is what PBES1 under the PKCS#12 OIDs is defined with.
pub fn pkcs12_key(
  passphrase : StringView,
  salt : BytesView,
  id~ : Int32,
  rounds~ : Int32,
  len~ : Int32,
) -> Bytes raise Refused {
  pkcs12_key_with(prf=Sha1, passphrase, salt, id~, rounds~, len~)
}
