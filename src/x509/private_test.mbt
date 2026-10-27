///|
fn public_of(spki : String) -> @x509.Key raise {
  @x509.Spki::read(@base16.decode(spki)[:]).key()
}

///|
fn refused_key(text : String) -> @asn1.Refused {
  try @x509.PrivateKey::pem(text) catch {
    e => e
  } noraise {
    _ => panic()
  }
}

///|
test "private key: every form reads to the key its certificate carries" {
  let cases = [
    (rsa_pkcs8, rsa_spki),
    (rsa_pkcs1, rsa_spki),
    (p256_pkcs8, p256_spki),
    (p256_sec1, p256_spki),
    (p384_pkcs8, p384_spki),
    (p521_pkcs8, p521_spki),
    (k256_pkcs8, k256_spki),
    (ed_pkcs8, ed_spki),
    (ed_pkcs8_v2, ed_spki),
    (short_sec1, short_spki),
    (padded_sec1, p256_spki),
    (bare_pkcs8, p256_spki),
  ]
  for case in cases {
    let (text, spki) = case
    assert_true(@x509.PrivateKey::pem(text).public() == public_of(spki))
  }
  assert_true(
    @x509.PrivateKey::pem(p256_pkcs8).public() != public_of(p384_spki),
  )
}

///|
test "private key: DER reads the same as the PEM around it" {
  let der = @x509.pem(rsa_pkcs1)
  assert_true(
    @x509.PrivateKey::read(der[:]).public() ==
    @x509.PrivateKey::pem(rsa_pkcs8).public(),
  )
}

///|
test "private key: what it signs, its public half verifies" {
  for text in [rsa_pkcs1, p384_pkcs8, ed_pkcs8] {
    let msg = b"signed by the key read from the file"
    match (@x509.PrivateKey::pem(text), @x509.PrivateKey::pem(text).public()) {
      (Rsa(k), Rsa(p)) => assert_true(p.verify(msg[:], k.sign(msg[:])))
      (Ec(k), Ec(p)) => assert_true(p.verify(msg[:], k.sign(msg[:])))
      (Ed25519(k), Ed25519(p)) => assert_true(p.verify(msg[:], k.sign(msg[:])))
      _ => fail("public half of another kind")
    }
  }
}

///|
test "private key: inconsistent keys are malformed" {
  for
    text in [foreign_point, curve_clash, ed_foreign, rsa_bad_primes, bare_sec1] {
    assert_true(refused_key(text) is Malformed(_))
  }
}

///|
test "private key: encrypted keys and keys that do not sign are unsupported" {
  for text in [encrypted_pkcs8, encrypted_legacy, x25519_pkcs8] {
    assert_true(refused_key(text) is Unsupported(_))
  }
  assert_true(refused_key(p256_spki) is Malformed(_))
}
