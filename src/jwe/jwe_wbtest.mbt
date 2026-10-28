// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn bytes(hex : String) -> Bytes {
  @base16.decode(hex) catch {
    _ => panic()
  }
}

///|
fn hex(b : BytesView) -> String {
  @base16.encode(b)
}

///|
/// One octet changed, the rest carried over: the cheapest forgery there is, and the one an
/// authenticator has to notice.
fn flip(b : BytesView, at : Int32) -> Bytes {
  let out = Buffer()
  for i in 0..<b.length() {
    if i == at {
      out.write_byte((b[i].to_int() ^ 0x01).to_byte())
    } else {
      out.write_byte(b[i])
    }
  }
  out.to_bytes()
}

///|
/// The wrapped-key examples of RFC 3394: the 128-bit KEK one in §4.1, cross-checked against
/// `openssl enc -id-aes128-wrap`, and three round trips for the key sizes JWE uses.
test "jwe: AES key wrap matches RFC 3394" {
  let kek = bytes("000102030405060708090A0B0C0D0E0F")
  let key = bytes("00112233445566778899AABBCCDDEEFF")
  let wrapped = wrap(kek[:], key[:])
  assert_eq(hex(wrapped[:]), "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
  assert_eq(unwrap(kek[:], wrapped[:]), key)
}

///|
/// A wrapped key from one KEK does not unwrap under another, and an edited one does not unwrap at
/// all: the initial value coming back out of the last round is the only check there is.
test "jwe: a wrapped key only unwraps under its own KEK" {
  let kek = bytes("000102030405060708090A0B0C0D0E0F")
  let other = bytes("0F0E0D0C0B0A09080706050403020100")
  let key = bytes("00112233445566778899AABBCCDDEEFF0001020304050607")
  let wrapped = wrap(kek[:], key[:])
  assert_eq(unwrap(kek[:], wrapped[:]), key)
  let refused = try {
    unwrap(other[:], wrapped[:]) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(refused)
  let edited = flip(wrapped[:], 20)
  let tampered = try {
    unwrap(kek[:], edited[:]) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(tampered)
}

///|
/// The CBC-HMAC construction, against the RFC 7518 §5.2.2.1 worked example: the plaintext is the
/// sentence about cipher systems, and the tag is over the additional data, the IV, the ciphertext
/// and the bit length of the additional data.
test "jwe: the CBC-HMAC construction matches its worked example" {
  let cek = bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  // The plaintext is 128 octets, so the padding is a whole block of sixteen 0x10 octets.
  let plain = bytes(
    "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
  )
  let iv = bytes("1af38c2dc2b96ffdd86694092341bc04")
  let aad = bytes(
    "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
  )
  let (cipher, tag) = content_seal(A128CbcHs256, cek, iv[:], plain[:], aad[:])
  assert_eq(
    hex(cipher[:]),
    "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db",
  )
  // 42 octets of additional data is 336 bits, which the tag appends as `0x0000000000000150`.
  assert_eq(hex(tag[:]), "652c3fa36b0a7c5b3219fab3a30bc1c4")
  assert_eq(
    content_open(A128CbcHs256, cek, iv[:], cipher[:], tag[:], aad[:]),
    plain,
  )
}

///|
/// Every content-encryption algorithm this package writes comes back, and a tag that has been
/// edited does not.
test "jwe: every content encryption opens what it seals" {
  let cases : Array[(Enc, Bytes)] = [
    (A128Gcm, bytes("000102030405060708090a0b")),
    (A192Gcm, bytes("000102030405060708090a0b")),
    (A256Gcm, bytes("000102030405060708090a0b")),
    (A128CbcHs256, bytes("000102030405060708090a0b0c0d0e0f")),
    (A192CbcHs384, bytes("000102030405060708090a0b0c0d0e0f")),
    (A256CbcHs512, bytes("000102030405060708090a0b0c0d0e0f")),
  ]
  let plain = bytes("746865207061796c6f6164")
  let aad = bytes("686561646572")
  for case in cases {
    let (enc, iv) = case
    let cek = bytes(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    )
    let key = cek[:enc.key_size()].to_owned()
    let (cipher, tag) = content_seal(enc, key, iv[:], plain[:], aad[:])
    assert_eq(content_open(enc, key, iv[:], cipher[:], tag[:], aad[:]), plain)
    let edited = flip(tag[:], 0)
    let refused = try {
      content_open(enc, key, iv[:], cipher[:], edited[:], aad[:]) |> ignore
      false
    } catch {
      Key => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
/// A sealed token carries the header first, and the shared key opens it: the whole path from
/// `encrypt` to `decrypt` for the two algorithms that need no other key.
test "jwe: dir and the wrapping algorithms round trip" {
  let plain = bytes("746865207061796c6f616420746861742074726176656c73")
  let iv16 = bytes("000102030405060708090a0b0c0d0e0f")
  let iv12 = bytes("000102030405060708090a0b")
  let cases : Array[(Alg, Enc, Bytes, Bytes)] = [
    (
      Dir,
      A256Gcm,
      bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
      iv12,
    ),
    (
      Dir,
      A128CbcHs256,
      bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
      iv16,
    ),
    (A128Kw, A128Gcm, bytes("000102030405060708090a0b0c0d0e0f"), iv12),
    (
      A256Kw,
      A256Gcm,
      bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
      iv12,
    ),
  ]
  for case in cases {
    let (alg, enc, shared, iv) = case
    let cek = if alg is Dir {
      None
    } else {
      Some(
        bytes(
          "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        )[:enc.key_size()].to_owned(),
      )
    }
    let token = encrypt(
      plain[:],
      key=Shared(shared),
      alg~,
      enc~,
      cek~,
      iv=iv[:],
    )
    let parts : Array[String] = []
    for p in token.split(".") {
      parts.push(p.to_owned())
    }
    assert_eq(parts.length(), 5)
    assert_eq(decrypt(token, key=Shared(shared), alg~, enc~), plain)
  }
}

///|
/// The header is authenticated: a token whose header has been edited to name another algorithm
/// does not open, and one opened under a caller who expected another algorithm is refused before
/// anything is decrypted.
test "jwe: the header is part of what is authenticated" {
  let shared = bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let token = encrypt(
    bytes("7061796c6f6164")[:],
    key=Shared(shared),
    alg=A256Kw,
    enc=A256Gcm,
    cek=Some(
      bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
    ),
    iv=bytes("000102030405060708090a0b")[:],
  )
  // Asking for another algorithm than the one the token names is refused outright.
  let confused = try {
    decrypt(token, key=Shared(shared), alg=A128Kw, enc=A256Gcm) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(confused)
  // A header swapped for one that says `dir` changes what the tag covers, so the key fails.
  let parts : Array[String] = []
  for p in token.split(".") {
    parts.push(p.to_owned())
  }
  let forged = @base64.encode(
    @utf8.encode("{\"alg\":\"dir\",\"enc\":\"A256GCM\"}"),
    kind=Url,
    padding=false,
  )
  let edited = forged +
    "." +
    parts[1] +
    "." +
    parts[2] +
    "." +
    parts[3] +
    "." +
    parts[4]
  let refused = try {
    decrypt(edited, key=Shared(shared), alg=Dir, enc=A256Gcm) |> ignore
    false
  } catch {
    Key => true
    _ => false
  }
  assert_true(refused)
}

///|
/// RSA-OAEP-256 against a key openssl made: the ciphertext in the fixture was wrapped by
/// `openssl pkeyutl` with the same digest and MGF, so opening it means the padding decoder agrees
/// with the one that wrote it rather than with itself. The other direction — a key this package
/// wraps, opened by `openssl pkeyutl -decrypt` — gives back the same content key; the command is
/// in `scripts/gen_credentials.py`, next to the fixture.
test "jwe: a key openssl wrapped to an RSA key opens" {
  let private_key = @rsa.PrivateKey::new(
    bytes(rsa_n)[:],
    bytes(rsa_e)[:],
    bytes(rsa_d)[:],
  ) catch {
    _ => panic()
  }
  let opened = private_key.decrypt(
    bytes(rsa_wrapped)[:],
    digest=@rsa.Sha256,
    mgf=@rsa.Sha256,
    label=b"",
  ) catch {
    _ => panic()
  }
  assert_eq(hex(opened[:]), rsa_cek)
  // And the same key in a token: the content key goes in wrapped, and comes back out.
  // The same key as openssl wrote it: the three numbers above are its parts, which is what makes
  // the fixture a key rather than a modulus with a signature on it.
  let from_pem = @x509.PrivateKey::pem(rsa_pem) catch { _ => panic() }
  match from_pem {
    Rsa(k) => assert_eq(k.public().modulus(), bytes(rsa_n))
    _ => panic()
  }
  let plain = bytes("746865207061796c6f6164")
  let token = encrypt(
    plain[:],
    key=Rsa(private_key.public()),
    alg=RsaOaep256,
    enc=A256Gcm,
    cek=Some(bytes(rsa_cek)),
    iv=bytes("000102030405060708090a0b")[:],
    seed=bytes(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      )[:],
  )
  assert_eq(
    decrypt(token, key=Rsa(private_key), alg=RsaOaep256, enc=A256Gcm),
    plain,
  )
  // A different key does not open it.
  let other = @rsa.PrivateKey::new(
    bytes("00d5f4c2b1a09080706050403020100f0e0d0c0b0a090807060504030201000f")[:],
    bytes(rsa_e)[:],
    bytes(rsa_d)[:],
  ) catch {
    _ => panic()
  }
  let refused = try {
    decrypt(token, key=Rsa(other), alg=RsaOaep256, enc=A256Gcm) |> ignore
    false
  } catch {
    Key => true
    _ => false
  }
  assert_true(refused)
}

///|
/// A token that is not five parts, or whose parts are not base64url, is malformed rather than
/// merely unsigned.
test "jwe: a string that is not a token is malformed" {
  let shared = bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  for text in ["", "a.b.c", "a.b.c.d.e.f", "a.b.c.d.!!!"] {
    let refused = try {
      decrypt(text, key=Shared(shared), alg=Dir, enc=A256Gcm) |> ignore
      false
    } catch {
      Malformed(_) => true
      _ => false
    }
    assert_true(refused)
  }
}
