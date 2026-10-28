// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The DER inside a PEM envelope, decoded here rather than through the certificate package,
/// which has no part in reading a container.
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
fn raw(hex : String) -> Bytes {
  @base16.decode(hex) catch {
    _ => panic()
  }
}

///|
/// The file `openssl pkcs12 -export` wrote: the MAC covers the AuthenticatedSafe as it travels, so
/// a file whose octets were edited anywhere in that buffer fails to verify even when it still
/// parses.
test "pkcs12: openssl's container verifies under its passphrase" {
  let pfx = parse(raw(modern)[:])
  assert_true(pfx.has_mac())
  assert_true(pfx.verify(passphrase~))
  assert_false(pfx.verify(passphrase="not the passphrase"))
}

///|
/// What the container held: the leaf certificate, the issuer the export carried alongside it, and
/// the private key — which has to be the PKCS#8 file itself, not a re-encoding of it.
test "pkcs12: the bags open to the certificate chain and the key" {
  let pfx = parse(raw(modern)[:])
  let contents = pfx.contents(passphrase~)
  assert_eq(contents.certs.length(), 2)
  assert_eq(contents.certs[0], body(certificate))
  assert_eq(contents.certs[1], body(issuer))
  assert_true(contents.key is Some(_))
  assert_eq(contents.key.unwrap(), body(key))
}

///|
/// An export that carried only the leaf still opens, with one certificate in the bag.
test "pkcs12: a container with one certificate reads" {
  let contents = parse(raw(single)[:]).contents(passphrase~)
  assert_eq(contents.certs.length(), 1)
  assert_eq(contents.certs[0], body(certificate))
  assert_eq(contents.key.unwrap(), body(key))
}

///|
/// A file written with `-nomac` has no digest to check, and the reader says so instead of calling
/// it tampered with: an unsigned container and a broken one are different answers.
test "pkcs12: a container without a MAC is not called tampered with" {
  let pfx = parse(raw(nomac)[:])
  assert_false(pfx.has_mac())
  assert_false(pfx.verify(passphrase~))
  // The certificate bag of this one travels unencrypted, the key bag shrouded — both are read.
  let contents = pfx.contents(passphrase~)
  assert_eq(contents.certs.length(), 1)
  assert_eq(contents.certs[0], body(certificate))
  assert_eq(contents.key.unwrap(), body(key))
}

///|
/// A passphrase that is not the file's is reported as such rather than as a broken file.
test "pkcs12: another passphrase does not open the bags" {
  let pfx = parse(raw(modern)[:])
  let refused = try {
    pfx.contents(passphrase="not the passphrase") |> ignore
    false
  } catch {
    Passphrase => true
    _ => false
  }
  assert_true(refused)
}

///|
/// What this package writes, OpenSSL reads and this package reads back: the MAC verifies under
/// the passphrase and the bags come out as they went in.
test "pkcs12: what this package writes comes back" {
  let certs : Array[Bytes] = [body(certificate), body(issuer)]
  let der = build(
    certs~,
    key=Some(body(key)),
    passphrase~,
    salt=raw("00112233445566778899aabbccddeeff")[:],
    iv=raw("000102030405060708090a0b0c0d0e0f")[:],
    mac_salt=raw("0f0e0d0c0b0a09080706050403020100")[:],
    scheme=Aes256Cbc,
    rounds=2048,
    mac_rounds=2048,
  )
  let pfx = parse(der[:])
  assert_true(pfx.has_mac())
  assert_true(pfx.verify(passphrase~))
  let contents = pfx.contents(passphrase~)
  assert_eq(contents.certs.length(), 2)
  assert_eq(contents.certs[0], body(certificate))
  assert_eq(contents.certs[1], body(issuer))
  assert_eq(contents.key.unwrap(), body(key))
}

///|
/// The older scheme writes a container the same reader opens: a file for a client that does not
/// know PBES2 still has to be a file this package can make.
test "pkcs12: the legacy scheme writes a container too" {
  let certs : Array[Bytes] = [body(certificate)]
  let der = build(
    certs~,
    key=Some(body(key)),
    passphrase~,
    salt=raw("00112233445566778899aabbccddeeff")[:],
    iv=raw("0001020304050607")[:],
    mac_salt=raw("0f0e0d0c0b0a09080706050403020100")[:],
    scheme=LegacyTripleDes,
    rounds=1000,
    mac_rounds=1000,
  )
  let pfx = parse(der[:])
  assert_true(pfx.verify(passphrase~))
  let contents = pfx.contents(passphrase~)
  assert_eq(contents.certs.length(), 1)
  assert_eq(contents.certs[0], body(certificate))
  assert_eq(contents.key.unwrap(), body(key))
}
