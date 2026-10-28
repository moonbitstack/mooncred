// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// AES Key Wrap (RFC 3394) is how A128KW, A192KW and A256KW put a content key inside a JWE: the key
// is encrypted a block at a time with the KEK, and each round mixes a counter into the first half
// so that a wrapped key cannot be moved into another position or another message.

///|
/// The default initial value of RFC 3394 §2.2.1.
let kw_iv : UInt64 = 0xA6A6A6A6A6A6A6A6

///|
/// The six rounds the algorithm runs.
let kw_rounds : Int32 = 6

///|
/// Wrap a content-encryption key under a key-encryption key. The plaintext must be a whole number
/// of eight-octet blocks and at least sixteen octets, which is what every CEK in RFC 7518 is.
pub fn wrap(kek : BytesView, key : BytesView) -> Bytes raise Refused {
  if key.length() < 16 || key.length() % 8 != 0 {
    raise Malformed("a key to wrap is not a run of eight-octet blocks")
  }
  let cipher = @aes.Cipher::new(kek) catch {
    _ => raise Malformed("a key-encryption key of the wrong length")
  }
  let n = key.length() / 8
  let blocks = FixedArray::make(n, 0UL)
  for i in 0..<n {
    blocks[i] = u64_of(key[i * 8:(i + 1) * 8])
  }
  let mut a = kw_iv
  for j in 0..<kw_rounds {
    for i in 0..<n {
      let joined = Buffer()
      joined.write_bytes(u64_bytes(a)[:])
      joined.write_bytes(u64_bytes(blocks[i])[:])
      let b = cipher.encrypt(joined.to_bytes()[:])
      a = u64_of(b[0:8]) ^ (n * j + i + 1).to_uint64()
      blocks[i] = u64_of(b[8:16])
    }
  }
  let out = Buffer()
  out.write_bytes(u64_bytes(a)[:])
  for i in 0..<n {
    out.write_bytes(u64_bytes(blocks[i])[:])
  }
  out.to_bytes()
}

///|
/// The inverse: recover the key, or `Malformed` when the octets are not a wrapped key under this
/// one. The integrity check is the initial value coming back out of the last round — that is the
/// whole reason the algorithm mixes a counter into it.
pub fn unwrap(kek : BytesView, wrapped : BytesView) -> Bytes raise Refused {
  if wrapped.length() < 24 || wrapped.length() % 8 != 0 {
    raise Malformed("a wrapped key is not a run of eight-octet blocks")
  }
  let cipher = @aes.Cipher::new(kek) catch {
    _ => raise Malformed("a key-encryption key of the wrong length")
  }
  let n = wrapped.length() / 8 - 1
  let mut a = u64_of(wrapped[0:8])
  let blocks = FixedArray::make(n, 0UL)
  for i in 0..<n {
    blocks[i] = u64_of(wrapped[(i + 1) * 8:(i + 2) * 8])
  }
  let mut j = kw_rounds - 1
  while j >= 0 {
    let mut i = n - 1
    while i >= 0 {
      a = a ^ (n * j + i + 1).to_uint64()
      let joined = Buffer()
      joined.write_bytes(u64_bytes(a)[:])
      joined.write_bytes(u64_bytes(blocks[i])[:])
      let b = cipher.decrypt(joined.to_bytes()[:])
      a = u64_of(b[0:8])
      blocks[i] = u64_of(b[8:16])
      i = i - 1
    }
    j = j - 1
  }
  if a != kw_iv {
    raise Malformed("a wrapped key that does not unwrap under this key")
  }
  let out = Buffer()
  for i in 0..<n {
    out.write_bytes(u64_bytes(blocks[i])[:])
  }
  out.to_bytes()
}

///|
fn u64_of(v : BytesView) -> UInt64 {
  let mut x = 0UL
  for i in 0..<8 {
    x = (x << 8) | v[i].to_uint64()
  }
  x
}

///|
fn u64_bytes(x : UInt64) -> Bytes {
  let out = Buffer()
  let mut i = 7
  while i >= 0 {
    out.write_byte(((x >> (i * 8)) & 0xFFUL).to_byte())
    i = i - 1
  }
  out.to_bytes()
}
