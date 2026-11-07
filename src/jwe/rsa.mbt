// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RSA key transport: the content key is encrypted to the recipient's public key and travels as
// the encrypted key. RSAES-PKCS1-v1_5 (RFC 8017 §7.2) and RSAES-OAEP (§7.1) are both here, and
// the older construction is the one that has to be asked for.

///|
/// Encrypt the content key to an RSA public key.
fn rsa_wrap(
  alg : Alg,
  key : @rsa.PublicKey,
  cek : BytesView,
  seed : BytesView,
) -> Bytes raise Refused {
  match alg {
    Rsa1_5 => pkcs1_wrap(key, cek, seed)
    RsaOaep =>
      key.encrypt(cek, seed~, digest=@rsa.Sha1, mgf=@rsa.Sha1, label=b"") catch {
        _ => raise Malformed("the RSA key cannot encrypt under OAEP")
      }
    RsaOaep256 =>
      key.encrypt(cek, seed~, digest=@rsa.Sha256, mgf=@rsa.Sha256, label=b"") catch {
        _ => raise Malformed("the RSA key cannot encrypt under OAEP")
      }
    _ => raise Malformed(alg.name() + " is not RSA key transport")
  }
}

///|
/// Recover the content key with the private half.
///
/// Every way the block can be wrong comes back as `Key`: which check failed is exactly what a
/// padding oracle reads off the answer, and RFC 8017 §7.2.2 asks for one answer to all of them.
fn rsa_unwrap(
  alg : Alg,
  key : @rsa.PrivateKey,
  wrapped : BytesView,
) -> Bytes raise Refused {
  match alg {
    Rsa1_5 => pkcs1_unwrap(key, wrapped)
    RsaOaep =>
      key.decrypt(wrapped, digest=@rsa.Sha1, mgf=@rsa.Sha1, label=b"") catch {
        _ => raise Key
      }
    RsaOaep256 =>
      key.decrypt(wrapped, digest=@rsa.Sha256, mgf=@rsa.Sha256, label=b"") catch {
        _ => raise Key
      }
    _ => raise Malformed(alg.name() + " is not RSA key transport")
  }
}

///|
/// EME-PKCS1-v1_5 (RFC 8017 §7.2.1): `00 02 PS 00 M`, with the padding string non-zero.
///
/// The padding has to be fresh randomness — it is what keeps the same content key from
/// producing the same block twice — so it comes from the caller, as the seed. Octets of zero
/// are replaced rather than refused: a caller that draws a seed from a source of randomness
/// should not have to filter it, and the loss of one octet's worth of entropy in a padding
/// string of at least eight is not a weakness.
fn pkcs1_wrap(
  key : @rsa.PublicKey,
  cek : BytesView,
  seed : BytesView,
) -> Bytes raise Refused {
  let size = key.size()
  let padding = size - cek.length() - 3
  if padding < 8 {
    raise Malformed("a content key too long for this RSA key")
  }
  if seed.length() < padding {
    raise Malformed("RSA1_5 needs \{padding} octets of seed for its padding")
  }
  let em = Buffer()
  em.write_byte(0x00)
  em.write_byte(0x02)
  for i in 0..<padding {
    let octet = seed[i].to_int()
    em.write_byte(if octet == 0 { (1 : Byte) } else { seed[i] })
  }
  em.write_byte(0x00)
  em.write_bytesview(cek)
  let block = em.to_bytes()
  key.rsaep(block[:]) catch {
    _ => raise Malformed("the RSA key cannot encrypt this block")
  }
}

///|
/// The inverse. The whole block is scanned before anything is decided, so the answer does not
/// depend on where the separator was: an implementation that stops at the first zero tells an
/// attacker how much of a modified block was padding.
fn pkcs1_unwrap(
  key : @rsa.PrivateKey,
  wrapped : BytesView,
) -> Bytes raise Refused {
  guard wrapped.length() == key.size() else { raise Key }
  let block = key.rsadp(wrapped) catch { _ => raise Key }
  let mut good = block[0].to_int() == 0 && block[1].to_int() == 2
  let mut at = -1
  for i in 2..<block.length() {
    if block[i].to_int() == 0 && at < 0 {
      at = i
    }
  }
  // RFC 8017 §7.2.2 asks for at least eight octets of padding and one separator.
  if at < 10 {
    good = false
  }
  guard good && at > 0 else { raise Key }
  block[at + 1:].to_owned()
}
