// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The request `openssl req` wrote with an extensionRequest attached: the subject, the scheme,
/// and the extensions it asked for all have to come back, because a CA that loses one of them
/// issues a certificate the requester cannot use.
test "csr: openssl's request reads with its extensions" {
  let req = Request::pem(request_ec)
  assert_eq(req.subject.cn(), Some("csr.example.com"))
  assert_eq(req.alg, "1.2.840.10045.4.3.2")
  assert_eq(req.exts.san.length(), 3)
  assert_eq(req.exts.san[0], @x509.Dns("csr.example.com"))
  assert_eq(req.exts.san[1], @x509.Dns("*.csr.example.com"))
  // The address arrives as the four octets of 192.0.2.7, not as text.
  assert_eq(req.exts.san[2], @x509.Ip(b"\xc0\x00\x02\x07"))
  assert_false(req.exts.ca)
  assert_true(req.exts.key_usage is Some(_))
  assert_eq(req.exts.eku, Some(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]))
}

///|
/// The signature is over the CertificationRequestInfo as it arrived, so the request verifies —
/// and the same request with one octet of its signature flipped does not. A reader that
/// re-encoded the info before checking would accept both.
test "csr: the signature covers the octets that arrived" {
  assert_true(Request::pem(request_ec).verified())
  assert_true(Request::pem(request_rsa).verified())
  assert_true(Request::pem(request_ed25519).verified())
  let der = @base64.decode(request_tampered) catch { _ => panic() }
  assert_false(parse(der[:]).verified())
}

///|
/// A request with no attributes carries an empty `[0]`, which is what OpenSSL writes when it has
/// nothing to ask for. An empty extension list is not the same as a request that failed to parse.
test "csr: a request without attributes reads as one with no extensions" {
  let req = Request::pem(request_bare)
  assert_true(req.verified())
  assert_eq(req.subject.cn(), Some("bare.example.com"))
  assert_eq(req.exts.san.length(), 0)
  assert_true(req.exts.key_usage is None)
  assert_eq(req.exts.eku, None)
}

///|
/// A request written here is one this package reads back: the subject, the extensionRequest and
/// the signature all survive the round trip, and the public key inside is the one that signed.
test "csr: what this package writes comes back and verifies" {
  let key = @x509.PrivateKey::pem(key_ec)
  let exts = {
    ..@x509.Exts::empty(),
    san: [@x509.Dns("written.example.com"), @x509.Dns("other.example.com")],
  }
  let der = self_signed(
    key,
    subject=@x509.common_name("written.example.com"),
    exts=Some(exts),
  )
  let read = parse(der[:])
  assert_true(read.verified())
  assert_eq(read.subject.cn(), Some("written.example.com"))
  assert_eq(read.exts.san.length(), 2)
  assert_eq(read.exts.san[1], @x509.Dns("other.example.com"))
  assert_true(read.asks_for(key.public()))
}

///|
/// The PEM form is the same request with an envelope around it, under the label `openssl req`
/// writes.
test "csr: the PEM form is what openssl reads" {
  let key = @x509.PrivateKey::pem(key_ec)
  let text = self_signed_pem(key, subject=@x509.common_name("pem.example.com"))
  assert_true(text.has_prefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
  assert_true(text.has_suffix("-----END CERTIFICATE REQUEST-----\n"))
  let read = Request::pem(text)
  assert_true(read.verified())
  assert_eq(read.to_pem(), text)
}

///|
/// A request for one key is not a request for another: the check a CA makes before it issues.
test "csr: asks_for tells the request's key from another" {
  let key = @x509.PrivateKey::pem(key_ec)
  let req = parse(
    self_signed(key, subject=@x509.common_name("who.example.com"))[:],
  )
  assert_true(req.asks_for(key.public()))
  assert_false(Request::pem(request_rsa).asks_for(key.public()))
}
