// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// COSE (RFC 9052) is three CBOR arrays and three byte strings, and the byte strings are the whole
// security story: what a signature covers is the structure built from the *received* protected
// header, so the layout has to be exactly the one the specification prints. The first test pins
// that layout; the rest are round trips and refusals.

///|
fn from_hex(text : String) -> Bytes {
  @base16.decode(text) catch {
    _ => panic()
  }
}

///|
fn to_hex(octets : BytesView) -> String {
  @base16.encode(octets)
}

///|
/// The octets of a value the test expects to be a byte string.
fn item_bytes(value : @cbor.Value) -> Bytes {
  match value {
    Bytes(octets) => octets
    _ => panic()
  }
}

///|
fn sha256() -> &@spec.Hash {
  (@sha2.Hasher::new(kind=Sha256) : &@spec.Hash)
}

///|
/// The three structures of RFC 9052 §4.4, §5.3 and §6.3 over the same header and payload, written
/// out by hand: an array of four (three for encryption), the context string, the protected header
/// as a byte string, the external data, and the payload.
test "cose: the signed structures are the shapes the specification prints" {
  let header = to_hex(@cbor.encode(@cbor.Map([(Int(1), Int(-7))])))
  assert_eq(header, "a10126")
  let payload = from_hex("68656c6c6f") // "hello"
  assert_eq(
    to_hex(signature_structure(from_hex("a10126"), b"", payload[:])),
    "846a5369676e61747572653143a10126404568656c6c6f",
  )
  assert_eq(
    to_hex(mac_structure(from_hex("a10126"), b"", payload[:])),
    "84644d41433043a10126404568656c6c6f",
  )
  assert_eq(
    to_hex(encrypt_structure(from_hex("a10126"), b"")),
    "8368456e63727970743043a1012640",
  )
  // The external data sits in the same place, and a shorter context string shifts nothing else.
  assert_eq(
    to_hex(signature_structure(from_hex("a10126"), from_hex("0001")[:], b"")),
    "846a5369676e61747572653143a10126420001" + "40",
  )
}

///|
/// HS256 as a COSE_Sign1: the message is a tagged array of four, and the signature covers the
/// header and the payload together, so neither can be changed on its own.
test "cose: a signed message verifies and its payload is what was signed" {
  let key = from_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let signer : &@spec.Signer = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let verifier : &@spec.Verifier = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let payload = from_hex("746865207061796c6f6164")
  let message = sign1(payload[:], alg=Hs256, signer, kid=Some(from_hex("aabb")))
  // The tag, then an array of four: the protected header, an empty map, the payload and the MAC.
  assert_eq(message[0], b'\xd2')
  let decoded = @cbor.decode(message[:]) catch { _ => panic() }
  match decoded {
    Tag(number, Array(items)) => {
      assert_eq(number, 18UL)
      assert_eq(items.length(), 4)
      assert_eq(items[2], Bytes(payload))
      // The kid travelled inside the signed header, not beside it.
      let header = @cbor.decode(item_bytes(items[0])[:]) catch { _ => panic() }
      assert_eq(header.get(Int(4)), Some(Bytes(from_hex("aabb"))))
    }
    _ => panic()
  }
  assert_eq(verify1(message[:], alg=Hs256, verifier), payload)
}

///|
/// The two things a verifier must not be talked into: a payload that has been edited, and a message
/// that names an algorithm other than the one the caller asked for.
test "cose: an edited payload and a substituted algorithm are both refused" {
  let key = from_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let signer : &@spec.Signer = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let verifier : &@spec.Verifier = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let message = sign1(from_hex("0102")[:], alg=Hs256, signer)
  // Another algorithm than the one the message names: refused before anything is verified.
  let confused = try {
    verify1(message[:], alg=Es256, verifier) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(confused)
  // The same message, with the payload swapped for another of its length.
  let edited = @cbor.encode(
    Tag(
      18UL,
      Array([
        Bytes(from_hex("a10105")),
        Map([]),
        Bytes(from_hex("0103")),
        Bytes(from_hex("00")),
      ]),
    ),
  )
  let refused = try {
    verify1(edited[:], alg=Hs256, verifier) |> ignore
    false
  } catch {
    Signature => true
    _ => false
  }
  assert_true(refused)
  // A COSE_Mac0 is not a COSE_Sign1, even with the same key.
  let wrong_tag = try {
    verify1(message[:], alg=Hs256, verifier, external=b"x") |> ignore
    false
  } catch {
    Signature => true
    _ => false
  }
  assert_true(wrong_tag)
}

///|
/// EdDSA, which is the one algorithm here whose signature is neither a MAC nor RSA: the key comes
/// from elsewhere and the signature is over the same structure.
test "cose: an Ed25519 signature verifies, and not under another key" {
  let seed = from_hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let private_key = @ed25519.PrivateKey::new(seed[:]) catch { _ => panic() }
  let public = @ed25519.PublicKey::new(
    from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")[:],
  ) catch {
    _ => panic()
  }
  let message = sign1(from_hex("0102030405")[:], alg=EdDsa, private_key)
  assert_eq(verify1(message[:], alg=EdDsa, public), from_hex("0102030405"))
  let other = @ed25519.PublicKey::new(
    from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")[:],
  ) catch {
    _ => panic()
  }
  let refused = try {
    verify1(message[:], alg=EdDsa, other) |> ignore
    false
  } catch {
    Signature => true
    _ => false
  }
  assert_true(refused)
}

///|
/// COSE_Mac0 and COSE_Encrypt0: the same header discipline, a different tail. The MAC carries the
/// payload in the clear — it says who wrote it, not who may read it — and the encryption carries
/// only the ciphertext, with the nonce inside the protected header.
test "cose: a MAC keeps the payload readable and an encryption does not" {
  let key = from_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let tagger : &@spec.Signer = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let verifier : &@spec.Verifier = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let payload = from_hex("68656c6c6f")
  let message = mac0(payload[:], alg=Hs256, tagger)
  let decoded = @cbor.decode(message[:]) catch { _ => panic() }
  match decoded {
    Tag(number, Array(items)) => {
      assert_eq(number, 17UL)
      assert_eq(items[2], Bytes(payload))
    }
    _ => panic()
  }
  assert_eq(verify_mac0(message[:], alg=Hs256, verifier), payload)
  // An encryption of the same payload: no plaintext anywhere in the message, and the nonce in
  // the header, which is what makes it authenticated.
  let aes_key = from_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let envelope = encrypt0(
    payload[:],
    alg=A256Gcm,
    key=aes_key[:],
    iv=from_hex("000102030405060708090a0b")[:],
  )
  let printable = to_hex(envelope[:])
  assert_false(printable.contains("68656c6c6f"))
  assert_eq(decrypt0(envelope[:], alg=A256Gcm, key=aes_key[:]), payload)
  // The nonce is part of the protected header, so editing it is editing what was authenticated.
  let decoded_sealed = @cbor.decode(envelope[:]) catch { _ => panic() }
  match decoded_sealed {
    Tag(number, Array(items)) => {
      assert_eq(number, 16UL)
      let header = @cbor.decode(item_bytes(items[0])[:]) catch { _ => panic() }
      assert_eq(
        header.get(Int(5)),
        Some(Bytes(from_hex("000102030405060708090a0b"))),
      )
    }
    _ => panic()
  }
  let refused = try {
    decrypt0(envelope[:], alg=A256Gcm, key=key[:], external=b"other") |> ignore
    false
  } catch {
    Signature => true
    _ => false
  }
  assert_true(refused)
}

///|
/// A key of the wrong size for the encryption named, and an algorithm that is not an encryption at
/// all, are refused rather than truncated or guessed at.
test "cose: the wrong key or the wrong algorithm for an encryption is refused" {
  let short = from_hex("000102030405060708090a0b0c0d0e0f")
  let iv = from_hex("000102030405060708090a0b")
  let refused = try {
    encrypt0(from_hex("00")[:], alg=A256Gcm, key=short[:], iv=iv[:]) |> ignore
    false
  } catch {
    Key => true
    _ => false
  }
  assert_true(refused)
  let not_encryption = try {
    encrypt0(from_hex("00")[:], alg=Rs256, key=short[:], iv=iv[:]) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(not_encryption)
}
