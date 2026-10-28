// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(text : String) -> Bytes {
  @base16.decode(text) catch {
    _ => panic()
  }
}

///|
fn to_hex(bytes : Bytes) -> String {
  @base16.encode(bytes[:])
}

///|
/// The seven worked examples of RFC 2268 §5. The first two pin the effective-key reduction —
/// sixty-three bits against sixty-four — which is the part of RC2 that is easy to get wrong and
/// impossible to notice when it is.
test "rc2: the RFC's own examples" {
  let cases : Array[(String, Int32, String, String)] = [
    ("0000000000000000", 63, "0000000000000000", "ebb773f993278eff"),
    ("ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"),
    ("3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"),
    ("88", 64, "0000000000000000", "61a8a244adacccf0"),
    ("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"),
    (
      "88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1",
    ),
    (
      "88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6",
    ),
  ]
  for case in cases {
    let (key, bits, plain, want) = case
    let out = rc2_block(hex(key)[:], bits, hex(plain)[:], decrypt=false)
    assert_eq(to_hex(out), want)
    assert_eq(to_hex(rc2_block(hex(key)[:], bits, out[:], decrypt=true)), plain)
  }
}

///|
/// Triple DES in EDE order, against the two-key and three-key forms.
test "des: triple DES encrypts under three keys and comes back" {
  // openssl enc -des-ede3 -K <key> on the eight octets 0123456789abcdef, and the CBC form of
  // the same plaintext under the IV 0001020304050607.
  let key = hex("0123456789abcdef23456789abcdef01456789abcdef0123")
  let plain = hex("0123456789abcdef")
  assert_eq(
    to_hex(tdes_block(key[:], plain[:], decrypt=false)),
    "f2afd84ee809e2b5",
  )
  let iv = hex("0001020304050607")
  let ciphertext = cbc_encrypt(key[:], iv[:], plain[:], 8, tdes=true)
  // The first block is what `openssl enc -des-ede3-cbc -nopad` prints for the same eight
  // octets; the second is the PKCS#7 padding this package adds.
  assert_eq(to_hex(ciphertext[:8].to_owned()), "04c9c882ffa783fa")
  assert_eq(ciphertext.length(), 16)
  assert_eq(
    to_hex(cbc_decrypt(key[:], iv[:], ciphertext[:], 8, tdes=true)),
    to_hex(plain),
  )
}

///|
/// A two-key triple DES is the three-key one with the first key repeated, which is a property
/// of the cipher rather than of this implementation but is worth pinning: a reader that gets it
/// backwards opens two-key files into rubbish.
test "des: two keys are the three-key form with the first repeated" {
  let pair = hex("0123456789abcdef23456789abcdef01")
  let three = hex("0123456789abcdef23456789abcdef010123456789abcdef")
  let block = hex("0011223344556677")
  let a = tdes_block(three[:], block[:], decrypt=false)
  let b = tdes_block(pair[:], block[:], decrypt=false)
  assert_eq(to_hex(a), to_hex(b))
  assert_eq(to_hex(tdes_block(pair[:], b[:], decrypt=true)), to_hex(block))
}

///|
/// The DER inside a PEM envelope, taken without the help of the certificate package — which
/// imports this one, so it cannot be reached from here.
fn body(pem : String) -> Bytes {
  let text = StringBuilder()
  for line in pem.split("\n") {
    let l = line.trim(chars=" \t\r").to_owned()
    if l.length() > 0 && !l.has_prefix("-----") {
      text.write_string(l)
    }
  }
  @base64.decode(text.to_string()) catch {
    _ => panic()
  }
}

///|
/// The files `openssl pkcs8` writes, in each scheme this package reads: the plaintext behind
/// every one of them is the same PKCS#8 PrivateKeyInfo, so a reader that gets a scheme wrong
/// says so by returning different octets rather than by failing politely.
test "pbe: openssl's encrypted keys open to the key they hold" {
  let want = body(plain_key)
  let files : Array[(String, String)] = [
    ("PBES2 AES-256-CBC", encrypted_aes256),
    ("PBES2 AES-128-CBC", encrypted_aes128),
    ("PBES2 triple DES-CBC", encrypted_3des),
    ("pbeWithSHAAnd3-KeyTripleDES-CBC", encrypted_pbes1_3des),
  ]
  for case in files {
    let (name, text) = case
    let encrypted = Encrypted::parse(body(text)[:])
    assert_eq(encrypted.name(), name)
    assert_eq(encrypted.decrypt(passphrase~), want)
  }
}

///|
/// A passphrase that is not the file's own is `Passphrase` rather than a plaintext that happens
/// to look reasonable: the padding check is what tells the two apart.
test "pbe: another passphrase does not open the file" {
  let encrypted = Encrypted::parse(body(encrypted_aes256)[:])
  let refused = try {
    encrypted.decrypt(passphrase="wrong") |> ignore
    false
  } catch {
    Passphrase => true
    _ => false
  }
  assert_true(refused)
}

///|
/// What this package writes, it reads, in every scheme it writes.
test "pbe: every scheme it writes comes back" {
  let plain = body(plain_key)
  let salt = hex("00112233445566778899aabbccddeeff")
  let iv16 = hex("000102030405060708090a0b0c0d0e0f")
  let iv8 = hex("0001020304050607")
  let cases : Array[(Scheme, Bytes)] = [
    (Aes128Cbc, iv16),
    (Aes192Cbc, iv16),
    (Aes256Cbc, iv16),
    (Aes128Gcm, iv16),
    (Aes192Gcm, iv16),
    (Aes256Gcm, iv16),
    (TripleDesCbc, iv8),
    (LegacyTripleDes, iv8),
    (LegacyRc2, iv8),
  ]
  for case in cases {
    let (scheme, iv) = case
    let written = encrypt(
      plain[:],
      passphrase~,
      salt=salt[:],
      iv=iv[:],
      scheme~,
      rounds=1000,
    )
    let read = Encrypted::parse(written[:])
    assert_eq(read.decrypt(passphrase~), plain)
  }
}

///|
/// A file written here is a file `openssl pkcs8` can read, which is the other half of the
/// interchange: the scheme name, the salt and the iteration count all have to be where OpenSSL
/// looks for them.
test "pbe: the DER this package writes carries the algorithm it says" {
  let plain = body(plain_key)
  let salt = hex("00112233445566778899aabbccddeeff")
  let written = encrypt(
    plain[:],
    passphrase~,
    salt=salt[:],
    iv=hex("000102030405060708090a0b0c0d0e0f")[:],
    scheme=Aes256Cbc,
    rounds=2048,
  )
  let read = Encrypted::parse(written[:])
  assert_eq(read.alg, "1.2.840.113549.1.5.13")
  assert_eq(read.cipher, Some("2.16.840.1.101.3.4.1.42"))
  assert_eq(
    read.kdf,
    Kdf::Pbkdf2(salt~, rounds=2048, prf="1.2.840.113549.2.9", length=None),
  )
  assert_eq(read.name(), "PBES2 AES-256-CBC")
}

///|
/// A PBES1 file this package writes is one it reads, and one that names the PKCS#12 scheme
/// rather than the PBES2 one — a reader of a 1999 file has to see the OID it expects.
test "pbe: the PBES1 schemes write the PKCS#12 algorithm identifiers" {
  let plain = body(plain_key)
  let salt = hex("00112233445566778899aabbccddeeff")
  let iv = hex("0001020304050607")
  let cases : Array[(Scheme, String)] = [
    (LegacyTripleDes, "1.2.840.113549.1.12.1.3"),
    (LegacyRc2, "1.2.840.113549.1.12.1.6"),
  ]
  for case in cases {
    let (scheme, oid) = case
    let written = encrypt(
      plain[:],
      passphrase~,
      salt=salt[:],
      iv=iv[:],
      scheme~,
      rounds=1000,
    )
    let read = Encrypted::parse(written[:])
    assert_eq(read.alg, oid)
    assert_eq(read.decrypt(passphrase~), plain)
  }
}
