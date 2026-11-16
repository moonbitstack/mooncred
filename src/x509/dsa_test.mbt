// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// DSA keys and certificates (RFC 3279 §2.3.2, RFC 5758 §3.1), from OpenSSL 3.2: a 2048-bit
// domain with a 256-bit subgroup, the key in PKCS#8, and a certificate signed with it under
// dsa-with-sha256.

///|
let dsa_cert : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIEYTCCBAegAwIBAgIUDvy5h7Oi4951tyQbG1piGcWkOLEwCwYJYIZIAWUDBAMC
  #|MA4xDDAKBgNVBAMMA2RzYTAeFw0yNjExMTYwMTQxMzFaFw00NjAxMTUwMTQxMzFa
  #|MA4xDDAKBgNVBAMMA2RzYTCCA0YwggI5BgcqhkjOOAQBMIICLAKCAQEArx1wypKr
  #|/FCKClDzivh9yVcAIlO856GaB/4WRVOKkHIiyYJOHslftMgUamtmK5f5vzN3zy5l
  #|lMejMRj/9H8ikiYBrETntd6ioMFsz7XLL1e+FkmsaJzOBerJ9vca0KPiT+KcRfMy
  #|Qv/13gS63eF0QikdL20OFJHck+4aYvUgGvvKOd2AKrxWo8nls+MOyz0gEW41B0kj
  #|ZWwtqVQyho0+FAtDrIVaXzgXDiy7fWz+u4t8tsdHfYifLIuoWeKQRVoMVg2tVK5N
  #|Y9Dzv4o0FRBEGGXiVbPwIz8ORYCviejYt/wXX+rCO/4auYVQ/EQOBZPq25iZrV0z
  #|WPufpCLOnriRwwIhAJLNN/0+osp1AASccTFJKJL+8LXhaXhN4avMxzWxUygvAoIB
  #|AB1Gu98iEX9Z/GJpPngdQS7USTuy9EqtfwdoK+4DAzUVfAVFsparf9jhttVwPbxg
  #|/kX73371RtpRIPG6PrJpZXqqssG2/WtpYqyISqcDg3vAtRq9WSbXdRyXA+nN3POS
  #|3/Mb9jrr09Ek9AT7ggNgyqdChhaj88uVnAzqHDyMiGRiCALE/caomG7OqfG+g+Ew
  #|9uzV0/QpBjPUTyVMQQq2MfOgL5To8Lrh1P19YAcr7MGBvbh3TJATbi3EpLzULzQa
  #|O5ZKWuGUZUKZLs9BLSMHFMEtIvoS+5Z6U05cav386C14YUcswBUotztAUl3KkaqL
  #|s2ESI9Ia9s1EKsNLbSVN4XIDggEFAAKCAQBfVdFfpMv8HrmHrX0BjVMchBzLL0i2
  #|xnsJZ9fd3RpRkYWv+gqqf+8Mp6WJMKrW9vM5zSWgpfKxDnUAmJOBQGJStnA/pyLy
  #|lCDq7HPcqIDENXHoFdU4mVaft9tRFNAOMsGIM/n5DOWMcXzobaZwXz1qHOost/YR
  #|lhOpHBmp457SaIjwZybxdDXVnyErPyYDRB+a8A7/KPkdN1UqFt/QpN/Qfam4hs1I
  #|Dg0PdR9BP07ua79GHsPWnJ/v3jsXhYcBflAcpkXWMv4f1on6sswpewofxRBvrcNV
  #|AYObVkZLgQk+esAeaoOQODGfMMYXTpIcZnS3GcWvDsN0YkNomqeav+AGo1MwUTAd
  #|BgNVHQ4EFgQUG3ayHb4nyd2wwyCXSTqdgUohwAwwHwYDVR0jBBgwFoAUG3ayHb4n
  #|yd2wwyCXSTqdgUohwAwwDwYDVR0TAQH/BAUwAwEB/zALBglghkgBZQMEAwIDRwAw
  #|RAIgVhZPnZdBC+DPFrkgH+/q2tlWCP4S8fg2Cg3GWxp8DUECIGEVsK5+Sn5fr9Jd
  #|QLeT0b63IDdKpDJ/pa3MkCMLLO18
  #|-----END CERTIFICATE-----

///|
let dsa_private : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIICZAIBADCCAjkGByqGSM44BAEwggIsAoIBAQCvHXDKkqv8UIoKUPOK+H3JVwAi
  #|U7znoZoH/hZFU4qQciLJgk4eyV+0yBRqa2Yrl/m/M3fPLmWUx6MxGP/0fyKSJgGs
  #|ROe13qKgwWzPtcsvV74WSaxonM4F6sn29xrQo+JP4pxF8zJC//XeBLrd4XRCKR0v
  #|bQ4UkdyT7hpi9SAa+8o53YAqvFajyeWz4w7LPSARbjUHSSNlbC2pVDKGjT4UC0Os
  #|hVpfOBcOLLt9bP67i3y2x0d9iJ8si6hZ4pBFWgxWDa1Urk1j0PO/ijQVEEQYZeJV
  #|s/AjPw5FgK+J6Ni3/Bdf6sI7/hq5hVD8RA4Fk+rbmJmtXTNY+5+kIs6euJHDAiEA
  #|ks03/T6iynUABJxxMUkokv7wteFpeE3hq8zHNbFTKC8CggEAHUa73yIRf1n8Ymk+
  #|eB1BLtRJO7L0Sq1/B2gr7gMDNRV8BUWylqt/2OG21XA9vGD+RfvffvVG2lEg8bo+
  #|smlleqqywbb9a2lirIhKpwODe8C1Gr1ZJtd1HJcD6c3c85Lf8xv2OuvT0ST0BPuC
  #|A2DKp0KGFqPzy5WcDOocPIyIZGIIAsT9xqiYbs6p8b6D4TD27NXT9CkGM9RPJUxB
  #|CrYx86AvlOjwuuHU/X1gByvswYG9uHdMkBNuLcSkvNQvNBo7lkpa4ZRlQpkuz0Et
  #|IwcUwS0i+hL7lnpTTlxq/fzoLXhhRyzAFSi3O0BSXcqRqouzYRIj0hr2zUQqw0tt
  #|JU3hcgQiAiAVa3izR5JIMIKkI6p3k6qpvtAHEGFGU8tW31ibrWlAbQ==
  #|-----END PRIVATE KEY-----

///|
test "dsa: a certificate OpenSSL signed with DSA verifies under its own key" {
  let cert = @x509.parse(@x509.pem(dsa_cert)[:])
  guard cert.spki.key() is Dsa(k) else { fail("not a DSA key") }
  assert_eq(k.domain().p().to_octets().length(), 256)
  assert_eq(k.domain().q().to_octets().length(), 32)
  assert_true(cert.signed_by(cert.spki))
  // One octet of the signature changed, and it no longer does.
  let bytes = cert.sig.bytes.to_array()
  bytes[bytes.length() - 1] = bytes[bytes.length() - 1] ^ b''
  let bent = @x509.signature_ok(
    cert.tbs,
    alg=cert.alg,
    params=cert.params,
    sig={ ..cert.sig, bytes: Bytes::from_array(bytes), },
    key=cert.spki,
  )
  assert_false(bent)
}

///|
test "dsa: the PKCS#8 key is the certificate's, and both encode back as they were read" {
  let cert = @x509.parse(@x509.pem(dsa_cert)[:])
  let key = @x509.PrivateKey::pem(dsa_private)
  guard key is Dsa(_) else { fail("not a DSA key") }
  assert_true(cert.spki.holds(key.public()))
  assert_true(@x509.PrivateKey::read(key.pkcs8()[:]).public() == key.public())
  assert_true(
    @x509.Spki::read(@x509.Spki::encode(key.public())[:]).key() == key.public(),
  )
}

///|
test "dsa: what this key signs, the certificate's key verifies" {
  let cert = @x509.parse(@x509.pem(dsa_cert)[:])
  let key = @x509.PrivateKey::pem(dsa_private)
  let tbs = b"a TBSCertificate"
  let sig = @x509.signature_value(key, tbs)
  let (alg, params) = @x509.algorithm(@x509.signature_algorithm(key)[:])
  let ok = @x509.signature_ok(
    tbs[:],
    alg~,
    params~,
    sig={ unused: 0, bytes: sig, },
    key=cert.spki,
  )
  assert_true(ok)
}

///|
test "dsa: a key without its domain is refused" {
  let cert = @x509.parse(@x509.pem(dsa_cert)[:])
  let bare = { ..cert.spki, domain: None, }
  let refused = try bare.key() catch {
    Malformed(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(refused)
}
