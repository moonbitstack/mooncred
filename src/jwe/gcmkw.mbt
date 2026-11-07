// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// AES-GCM key wrapping (RFC 7518 §4.7): the content key is encrypted under a shared key with
// an AEAD, and the nonce and tag travel in the header beside the ciphertext. It buys what AES
// key wrap does not — the header of the recipient is authenticated with the key.

///|
/// The nonce an AES-GCM wrap uses: twelve octets, the size RFC 7518 §4.7.1.1 asks for.
let gcm_kw_iv : Int32 = 12

///|
/// Encrypt the content key: `(ciphertext, tag)`.
fn gcm_kw_wrap(
  kek : BytesView,
  cek : BytesView,
  iv : BytesView,
) -> (Bytes, Bytes) raise Refused {
  if iv.length() != gcm_kw_iv {
    raise Malformed("an AES-GCM wrap takes a \{gcm_kw_iv}-octet nonce")
  }
  let cipher = @aes.Cipher::new(kek) catch {
    _ => raise Malformed("a key-encryption key of the wrong length")
  }
  let gcm = @gcm.Gcm::new(cipher, tag=16) catch {
    _ => raise Malformed("GCM refused the parameters")
  }
  let whole = gcm.seal(nonce=iv, plain=cek, aad=b"")
  let cut = whole.length() - 16
  (whole[:cut].to_owned(), whole[cut:].to_owned())
}

///|
/// The inverse, with the tag checked before anything is returned.
fn gcm_kw_unwrap(
  kek : BytesView,
  cipher_text : BytesView,
  tag : BytesView,
  iv : BytesView,
) -> Bytes raise Refused {
  if iv.length() != gcm_kw_iv {
    raise Malformed("an AES-GCM wrap takes a \{gcm_kw_iv}-octet nonce")
  }
  if tag.length() != 16 {
    raise Malformed("an AES-GCM tag is sixteen octets")
  }
  let cipher = @aes.Cipher::new(kek) catch {
    _ => raise Malformed("a key-encryption key of the wrong length")
  }
  let gcm = @gcm.Gcm::new(cipher, tag=16) catch {
    _ => raise Malformed("GCM refused the parameters")
  }
  let joined = Buffer()
  joined.write_bytesview(cipher_text)
  joined.write_bytesview(tag)
  gcm.open(nonce=iv, cipher=joined.to_bytes()[:], aad=b"") catch {
    _ => raise Key
  }
}
