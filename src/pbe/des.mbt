// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DES and triple DES, which the PBES1 schemes PKCS#12 files carry are keyed with (RFC 7292
// §B.1: pbeWithSHAAnd3-KeyTripleDES-CBC). Only read out of an old file and written back into
// one — PBES1 exists because it was once the only thing a mail client could decrypt, and
// nothing issued today should start there.
//
// The tables are FIPS 46-3's, written as the bit numbers that permutation takes its output bits
// from, counting the leftmost input bit as 1.

///|
let des_ip : Array[Int32] = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30,
  22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51,
  43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15,
  7,
]

///|
let des_fp : Array[Int32] = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54,
  22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3,
  43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57,
  25,
]

///|
let des_e : Array[Int32] = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16,
  17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28,
  29, 30, 31, 32, 1,
]

///|
let des_p : Array[Int32] = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32,
  27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]

///|
let des_pc1 : Array[Int32] = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]

///|
let des_pc2 : Array[Int32] = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20,
  13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
]

///|
let des_shift : Array[Int32] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

///|
let des_sboxes : Array[Array[Int32]] = [
  [
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13,
    1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10,
    5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  ],
  [
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8,
    14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3,
    2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  ],
  [
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10,
    2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14,
    7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  ],
  [
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0,
    3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2,
    8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  ],
  [
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13,
    1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0,
    14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  ],
  [
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9,
    5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13,
    11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  ],
  [
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1,
    10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5,
    9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  ],
  [
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7,
    4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3,
    5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  ],
]

///|
/// The bits `table` names, taken from the left of `x` counted as a `width`-bit value.
fn pick(x : UInt64, width : Int32, table : Array[Int32]) -> UInt64 {
  let mut out = 0UL
  for t in table {
    out = (out << 1) | ((x >> (width - t)) & 1UL)
  }
  out
}

///|
fn u64_of(bytes : BytesView) -> UInt64 {
  let mut v = 0UL
  for i in 0..<bytes.length() {
    v = (v << 8) | bytes[i].to_int().to_uint64()
  }
  v
}

///|
fn bytes_of(value : UInt64, width : Int32) -> Bytes {
  let out = Buffer()
  for i in 0..<width {
    out.write_byte(
      ((value >> ((width - 1 - i) * 8)) & 0xffUL).to_int().to_byte(),
    )
  }
  out.to_bytes()
}

///|
fn rotl28(x : UInt64, n : Int32) -> UInt64 {
  ((x << n) | (x >> (28 - n))) & 0x0fffffffUL
}

///|
/// The sixteen 48-bit subkeys of one key, in the order the rounds use them.
fn des_keys(key : BytesView) -> Array[UInt64] {
  // DES takes eight octets; a longer view is a triple DES key whose first third is this one.
  let folded = pick(u64_of(key[0:8]), 64, des_pc1)
  let mut c = folded >> 28
  let mut d = folded & 0x0fffffffUL
  let out : Array[UInt64] = []
  for s in des_shift {
    c = rotl28(c, s)
    d = rotl28(d, s)
    out.push(pick((c << 28) | d, 56, des_pc2))
  }
  out
}

///|
fn des_round(r : UInt64, key : UInt64) -> UInt64 {
  let spread = pick(r, 32, des_e) ^ key
  let mut s = 0UL
  for i in 0..<8 {
    let six = ((spread >> (42 - 6 * i)) & 0x3fUL).to_int()
    let row = ((six >> 4) & 2) | (six & 1)
    let col = (six >> 1) & 0x0f
    s = (s << 4) | des_sboxes[i][row * 16 + col].to_uint64()
  }
  pick(s, 32, des_p)
}

///|
/// One 8-octet block. A key of 8 octets is DES; 16 or 24 is triple DES in EDE order, the
/// two-key form repeating the first key third.
fn des_block(key : BytesView, block : BytesView, decrypt~ : Bool) -> Bytes {
  let forward = des_keys(key)
  let order : Array[UInt64] = []
  for i in 0..<16 {
    order.push(if decrypt { forward[15 - i] } else { forward[i] })
  }
  let placed = pick(u64_of(block), 64, des_ip)
  let mut left = placed >> 32
  let mut right = placed & 0xffffffffUL
  for i in 0..<16 {
    let next = left ^ des_round(right, order[i])
    left = right
    right = next
  }
  bytes_of(pick((right << 32) | left, 64, des_fp), 8)
}

///|
fn xor8(a : BytesView, b : BytesView) -> Bytes {
  let out = Buffer()
  for i in 0..<a.length() {
    out.write_byte((a[i].to_int() ^ b[i].to_int()).to_byte())
  }
  out.to_bytes()
}

///|
/// The three-key triple DES in EDE order over one block: encrypt under the first key, decrypt
/// under the second, encrypt under the third.
fn tdes_block(
  key : BytesView,
  block : BytesView,
  decrypt~ : Bool,
) -> Bytes raise Refused {
  match key.length() {
    8 => des_block(key, block, decrypt~)
    16 => {
      let first = key[0:8]
      let second = key[8:16]
      if decrypt {
        des_block(
          first,
          des_block(
            second,
            des_block(first, block, decrypt=true)[:],
            decrypt=false,
          )[:],
          decrypt=true,
        )
      } else {
        des_block(
          first,
          des_block(
            second,
            des_block(first, block, decrypt=false)[:],
            decrypt=true,
          )[:],
          decrypt=false,
        )
      }
    }
    24 => {
      let first = key[0:8]
      let second = key[8:16]
      let third = key[16:24]
      if decrypt {
        des_block(
          first,
          des_block(
            second,
            des_block(third, block, decrypt=true)[:],
            decrypt=false,
          )[:],
          decrypt=true,
        )
      } else {
        des_block(
          third,
          des_block(
            second,
            des_block(first, block, decrypt=false)[:],
            decrypt=true,
          )[:],
          decrypt=false,
        )
      }
    }
    n => raise Unsupported("a triple DES key of \{n} octets")
  }
}

///|
/// CBC with PKCS#7 padding, the mode every one of these schemes uses.
fn cbc_encrypt(
  key : BytesView,
  iv : BytesView,
  plain : BytesView,
  width : Int32,
  tdes~ : Bool,
) -> Bytes raise Refused {
  if iv.length() != width {
    raise Malformed("an IV of \{iv.length()} octets for a \{width}-octet block")
  }
  let pad = width - plain.length() % width
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
    let block = xor8(padded[off:off + width], chain[:])
    let out_block = if tdes {
      tdes_block(key, block[:], decrypt=false)
    } else {
      let cipher = @aes.Cipher::new(key) catch {
        _ => raise Malformed("an AES key of the wrong length")
      }
      cipher.encrypt(block[:])
    }
    out.write_bytes(out_block[:])
    chain = out_block
    off = off + width
  }
  out.to_bytes()
}

///|
fn cbc_decrypt(
  key : BytesView,
  iv : BytesView,
  ciphertext : BytesView,
  width : Int32,
  tdes~ : Bool,
) -> Bytes raise Refused {
  if ciphertext.length() == 0 || ciphertext.length() % width != 0 {
    raise Malformed("a ciphertext that is not a run of whole blocks")
  }
  if iv.length() != width {
    raise Malformed("an IV of \{iv.length()} octets for a \{width}-octet block")
  }
  let out = Buffer()
  let mut chain = iv.to_owned()
  let mut off = 0
  while off < ciphertext.length() {
    let block = ciphertext[off:off + width]
    let opened = if tdes {
      tdes_block(key, block, decrypt=true)
    } else {
      let cipher = @aes.Cipher::new(key) catch {
        _ => raise Malformed("an AES key of the wrong length")
      }
      cipher.decrypt(block)
    }
    out.write_bytes(xor8(opened[:], chain[:])[:])
    chain = block.to_owned()
    off = off + width
  }
  let padded = out.to_bytes()
  let pad = padded[padded.length() - 1].to_int()
  // RFC 5652 §6.3: every pad octet must carry the pad length, so a wrong key is told apart from
  // a right one rather than decrypting to something plausible.
  if pad < 1 || pad > width {
    raise Passphrase
  }
  for i in 1..<=pad {
    if padded[padded.length() - i].to_int() != pad {
      raise Passphrase
    }
  }
  padded[:padded.length() - pad].to_owned()
}
