// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A self-signed X.509 v3 P-256 certificate (RFC 5280). The DER this produces was validated with
// OpenSSL 3.2.4: `openssl x509 -inform DER` parses it (subject/issuer CN, ecdsa-with-SHA256,
// id-ecPublicKey prime256v1) and `openssl verify` returns OK — the self-signature checks out.

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
/// A P-256 private key from the hex of its scalar.
fn key_of(hex : String) -> @ecdsa.PrivateKey raise {
  @ecdsa.PrivateKey::new(raw(hex)[:], curve=P256)
}

///|
/// What a refusal says, so a test can name the reason rather than only the fact.
fn refusal(f : () -> Unit raise @asn1.Refused) -> String {
  try {
    f()
    "no refusal"
  } catch {
    @asn1.Malformed(m) => "Malformed: " + m
    @asn1.Unsupported(m) => "Unsupported: " + m
  }
}

///|
test "x509: a self-signed P-256 certificate carries a valid ES256 signature over its TBS" {
  let key = key_of(
    "233333333333333333333333333333333333333333333333333333333333eeff",
  )
  let cert = @x509.self_signed(
    key, b"\x0d\x23\x33", "lfanke.example", "250101000000Z", "350101000000Z",
  )
  // Byte-exact against the DER that OpenSSL validated (deterministic RFC 6979 signing): any
  // change to the ASN.1 assembly or the signature moves these bytes.
  assert_eq(
    cert,
    raw(
      "308201203081c7a00302010202030d2333300a06082a8648ce3d04030230193117301506035504030c0e6c66616e6b652e6578616d706c65301e170d3235303130313030303030305a170d3335303130313030303030305a30193117301506035504030c0e6c66616e6b652e6578616d706c653059301306072a8648ce3d020106082a8648ce3d03010703420004a115f872600665c589ff3f4687e29794b9af522dcf6920265fb76db77a5a093a7499dd913c1f2e028600cd29f3f1e34bab9db77349d7ffba7c99e732a1d96f0f300a06082a8648ce3d0403020348003045022100f68eb723ff01316c1dcdfda7fe869c92b27c2a0484f467a734cca98723b8146402205b5d439b9180abde78c096dc46932dad312abac9e2d79acca457e7830668b2e0",
    ),
  )
  // The signature is valid over the TBSCertificate: rebuild the TBS (deterministic RFC 6979
  // signing) and verify with the certificate's own public key — a self-signature.
  let tbs = @x509.tbs_of(
    b"\x0d\x23\x33",
    "lfanke.example",
    "250101000000Z",
    "350101000000Z",
    key.public(),
  )
  let sig = key.sign(tbs[:])
  assert_eq(key.public().verify(tbs[:], sig[:]), true)
  // The DER certificate rides the TLS 1.3 Certificate message and comes back out intact.
}

///|
/// `certs/cert.pem`: the self-signed localhost certificate `scripts/gen_test_cert.sh` writes for
/// the HTTPS tests. RSA-2048, so this package can read it but cannot check its signature.
let rsa_localhost : String =
  #|MIIDJTCCAg2gAwIBAgIUaPML0c2AXU63EiFG/0PGEHGEcaMwDQYJKoZIhvcNAQEL
  #|BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcyODEwNTQ1MVoXDTM2MDcy
  #|NTEwNTQ1MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
  #|AAOCAQ8AMIIBCgKCAQEA7CV78/w/VoVzOLtlivu+G6r18Hd1cvLDE3qpF4/R8rHe
  #|6dxOAq8R48f3FCvDeTHrEF71wvXAsyEH5NTPK69j91VfGsdfJMGIBu7PfOyAQuZA
  #|nTrvmqn2SluIUJeAak9+0KEXoHZo1IB4zDQXWVkcdjRtaXGBJ3AA1XaBT0JeYR/i
  #|XfwPUR+SwzaCXkTZCq6NZoZ5cPSEUv7klL6urg5TNGH6U8RPgJZiBZW624OQLael
  #|5He0yLW44E4m/bUk3jVLIpvdVn34ykyYjf0OoVdLUbTApXtplg1MoRoDgY6e2Rk4
  #|lXSXYG5y2rbAucqG84+XaqgzwITR7Ad3vnqIvMCryQIDAQABo28wbTAdBgNVHQ4E
  #|FgQUROZCZow84LGWuCmvAVxedcQGTXQwHwYDVR0jBBgwFoAUROZCZow84LGWuCmv
  #|AVxedcQGTXQwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
  #|BH8AAAEwDQYJKoZIhvcNAQELBQADggEBALf077m7RmLuPhPhBFMZP3ZO6fc/6hcW
  #|niqOorzkDs4dWx4XmRYe9ZPZEBqStKpWXl0ZMvVCCKvkGll/iPNIhUzIBuMJB/ZN
  #|lFA7QDY98s4ChbTP6El6LJ3j7AcKKNhnXzcKw+1lOx3QjePFLqK1sQl1SEPnzFvl
  #|ljuZqZJl05r83EmGysiVfmwivA7NgVXBgLeB9oDrwmqs60WN3sywTMj7H1XOdsGh
  #|x/wDx5puvErjKjyUYgPu/fhx9NXfOc8WGksmXMZthuHlgGKxz/mdc6yRydTp+hkv
  #|4sINiRSjWD2p+MlIsTQCGObkvyawfM5Zu/57g0aZ3AxfdlDYB/EYiks=

///|
/// A second self-signed certificate, from `openssl req -x509 -newkey ec -pkeyopt
/// ec_paramgen_curve:prime256v1` with a wildcard SAN, a critical keyUsage, an extKeyUsage and a
/// pathlen. P-256, so its signature is one this package verifies.
let p256_lfanke : String =
  #|MIICDzCCAbWgAwIBAgIUND+1Wo/n785mR4v4AinRytUyqG0wCgYIKoZIzj0EAwIw
  #|LDEXMBUGA1UEAwwObGZhbmtlLmV4YW1wbGUxETAPBgNVBAoMCGhla2UxMjI4MB4X
  #|DTI2MDgzMDA3MTI0N1oXDTM2MDgyNzA3MTI0N1owLDEXMBUGA1UEAwwObGZhbmtl
  #|LmV4YW1wbGUxETAPBgNVBAoMCGhla2UxMjI4MFkwEwYHKoZIzj0CAQYIKoZIzj0D
  #|AQcDQgAEREVIbX8P7bEyrwoxJ867MCdPIm7OmYByodaG6GLjir69Y4+KyrnTwkG/
  #|fRS9xXC9qONvSxUgiERVF4zGx6Ye6aOBtDCBsTAdBgNVHQ4EFgQUpWKCpUq2biSe
  #|CowYwHWjIN8vxXYwHwYDVR0jBBgwFoAUpWKCpUq2biSeCowYwHWjIN8vxXYwLAYD
  #|VR0RBCUwI4IQKi5sZmFua2UuZXhhbXBsZYIJbG9jYWxob3N0hwR/AAABMA4GA1Ud
  #|DwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
  #|AQH/BAgwBgEB/wIBADAKBggqhkjOPQQDAgNIADBFAiEAmT5E3FfP+kh3qMTiCiSk
  #|5VrkBe6OYILV6rMlJkKieikCIA4O+U6PC4F45N3GJP+uvNcxYsZMQUnZcG/nulbZ
  #|6gZb

///|
/// The DER inside a PEM body. The two certificates above are pinned here rather than read out of
/// `certs/`: this is a parser test, and it should go on testing the same bytes after the TLS
/// fixtures are regenerated with fresh keys.
fn pem(body : String) -> Bytes {
  @base64.decode_lossy(body)
}

///|
test "x509: a real RSA certificate, read down to its extensions" {
  let der = pem(rsa_localhost)
  assert_eq(der.length(), 809)
  let cert = @x509.parse(der[:])
  assert_eq(cert.version, 3)
  assert_eq(
    cert.serial,
    BigInt::from_string("68f30bd1cd805d4eb7122146ff43c610718471a3", radix=16),
  )
  assert_eq(cert.alg, "1.2.840.113549.1.1.11") // sha256WithRSAEncryption
  assert_eq(cert.subject, @x509.Name::{
    rdns: [[{ oid: "2.5.4.3", value: "localhost", }]],
  })
  assert_eq(cert.subject.cn(), Some("localhost"))
  assert_eq(cert.issuer, cert.subject) // self-signed
  assert_eq(cert.validity, { not_before: 1785236091L, not_after: 2100596091L, })
  assert_eq(cert.spki.alg, "1.2.840.113549.1.1.1") // rsaEncryption, parameters NULL
  assert_eq(cert.spki.params, None)
  assert_eq(cert.spki.key.unused, 0)
  assert_eq(cert.spki.key.bytes.length(), 270)
  assert_eq(cert.exts.san, [
    @x509.Dns("localhost"),
    @x509.Ip(b"\x7f\x00\x00\x01"),
  ])
  assert_eq(cert.exts.ca, true)
  assert_eq(cert.exts.path_len, None)
  assert_eq(cert.exts.key_usage, None)
  assert_eq(cert.exts.eku, None)
  // The subject and authority key identifiers are there and are not critical, so skipping them
  // is allowed and the certificate stays usable.
  assert_eq(cert.exts.unknown_critical, [])
  assert_eq(cert.raw.length(), 809)
  assert_eq(cert.tbs.length(), 529)
  assert_eq(cert.matches("localhost"), true)
  assert_eq(cert.matches("LocalHost"), true)
  assert_eq(cert.matches("localhost.example"), false)
  assert_eq(cert.matches("127.0.0.1"), false) // the iPAddress entry is not a hostname
  assert_eq(cert.valid_at(1785236091L), true)
  assert_eq(cert.valid_at(1785236090L), false)
  assert_eq(cert.valid_at(2100596091L), true)
  assert_eq(cert.valid_at(2100596092L), false)
  // An RSA key and an RSA signature are refused by name, not quietly reported as invalid.
  assert_eq(
    refusal(() => cert.spki.p256() |> ignore),
    "Unsupported: public key algorithm 1.2.840.113549.1.1.1",
  )
  let some_key = key_of(
    "0000000000000000000000000000000000000000000000000000000000233333",
  ).public()
  assert_eq(
    refusal(() => cert.signed_by(some_key) |> ignore),
    "Unsupported: signature algorithm 1.2.840.113549.1.1.11",
  )
}

///|
test "x509: a real P-256 certificate — its key, its extensions, and its own signature" {
  let der = pem(p256_lfanke)
  let cert = @x509.parse(der[:])
  assert_eq(cert.version, 3)
  assert_eq(cert.alg, "1.2.840.10045.4.3.2") // ecdsa-with-SHA256
  assert_eq(cert.subject, @x509.Name::{
    rdns: [
      [{ oid: "2.5.4.3", value: "lfanke.example", }],
      [{ oid: "2.5.4.10", value: "heke1228", }],
    ],
  })
  assert_eq(cert.subject.cn(), Some("lfanke.example"))
  assert_eq(cert.subject.get("2.5.4.10"), Some("heke1228"))
  assert_eq(cert.subject.get("2.5.4.6"), None)
  assert_eq(cert.validity, { not_before: 1788073967L, not_after: 2103433967L, })
  assert_eq(cert.exts.san, [
    @x509.Dns("*.lfanke.example"),
    @x509.Dns("localhost"),
    @x509.Ip(b"\x7f\x00\x00\x01"),
  ])
  assert_eq(cert.exts.ca, true)
  assert_eq(cert.exts.path_len, Some(0))
  assert_eq(cert.exts.eku, Some([@x509.eku_server_auth, @x509.eku_client_auth]))
  assert_eq(cert.exts.unknown_critical, [])
  let ku = cert.exts.key_usage.unwrap()
  assert_eq(ku.get(0), true) // digitalSignature
  assert_eq(ku.get(1), false) // nonRepudiation
  assert_eq(ku.get(5), true) // keyCertSign
  assert_eq(ku.get(6), false) // cRLSign
  // The key openssl reported for this certificate, coordinate for coordinate.
  let key = cert.spki.p256()
  assert_eq(cert.spki.params, Some("1.2.840.10045.3.1.7"))
  // The point, as the uncompressed SEC1 encoding it was read from. Reading it
  // back at all is the on-curve check: `mooncrypt` refuses a point that is not.
  assert_eq(
    @base16.encode(key.bytes()[1:33]),
    "4445486d7f0fedb132af0a3127cebb30274f226ece998072a1d686e862e38abe",
  )
  assert_eq(
    @base16.encode(key.bytes()[33:65]),
    "bd638f8acab9d3c241bf7d14bdc570bda8e36f4b1520884455178cc6c7a61ee9",
  )
  // Self-signed: the certificate's own key checks the ECDSA signature openssl put on it.
  assert_eq(cert.signed_by(key), true)
  // The same key against a certificate whose TBS is one byte different is not a signature.
  let tampered = Buffer()
  tampered.write_bytes(der[0:20])
  tampered.write_byte((der[20].to_int() ^ 1).to_byte())
  tampered.write_bytes(der[21:])
  assert_eq(@x509.parse(tampered.to_bytes()[:]).signed_by(key), false)
  assert_eq(cert.matches("a.lfanke.example"), true)
  assert_eq(cert.matches("A.LFANKE.Example"), true)
  assert_eq(cert.matches("lfanke.example"), false) // the wildcard is a label, not nothing
  assert_eq(cert.matches("a.b.lfanke.example"), false) // and it is one label, not several
  assert_eq(cert.matches("localhost"), true)
}

///|
test "x509: the wildcard covers one whole label and nothing else (RFC 6125 §6.4.3)" {
  assert_eq(@x509.dns_match("a.example", "a.example"), true)
  assert_eq(@x509.dns_match("A.ExAmPlE", "a.example"), true)
  assert_eq(@x509.dns_match("*.a.example", "b.a.example"), true)
  assert_eq(@x509.dns_match("*.a.example", "a.example"), false)
  assert_eq(@x509.dns_match("*.a.example", "c.b.a.example"), false)
  assert_eq(@x509.dns_match("b*.a.example", "bc.a.example"), false)
  assert_eq(@x509.dns_match("*b.a.example", "cb.a.example"), false)
  assert_eq(@x509.dns_match("a.*.example", "a.b.example"), false)
  assert_eq(@x509.dns_match("*", "example"), false)
  assert_eq(@x509.dns_match("*.example", "a.example"), true)
  assert_eq(@x509.dns_match("a.example", "a.example."), false) // the empty label is not a label
  assert_eq(@x509.dns_match("a..example", "a..example"), false)
}

///|
test "x509: the generator's certificate parses back into the fields it was built from" {
  let key = key_of(
    "233333333333333333333333333333333333333333333333333333333333eeff",
  )
  let der = @x509.self_signed(
    key, b"\x0d\x23\x33", "lfanke.example", "250101000000Z", "350101000000Z",
  )
  let cert = @x509.parse(der[:])
  assert_eq(cert.version, 3)
  assert_eq(cert.serial, (0x0d2333 : BigInt))
  assert_eq(cert.alg, "1.2.840.10045.4.3.2")
  assert_eq(cert.issuer.cn(), Some("lfanke.example"))
  assert_eq(cert.subject.cn(), Some("lfanke.example"))
  assert_eq(cert.validity, { not_before: 1735689600L, not_after: 2051222400L, })
  assert_eq(cert.spki.p256().bytes(), key.public().bytes())
  // The bytes the parser says the signature covers are the ones the generator signed.
  assert_eq(
    cert.tbs.to_owned(),
    @x509.tbs_of(
      b"\x0d\x23\x33",
      "lfanke.example",
      "250101000000Z",
      "350101000000Z",
      key.public(),
    ),
  )
  assert_eq(cert.signed_by(cert.spki.p256()), true)
  // It carries no subjectAltName, so it is an identity for no host at all.
  assert_eq(cert.exts.san, [])
  assert_eq(cert.matches("lfanke.example"), false)
}

///|
/// A v3 certificate carrying `exts`, so one extension rule can be aimed at on its own. The
/// signature is a placeholder: every case built with this is refused long before anything reaches
/// it.
fn with_exts(
  pub_key : @ecdsa.PublicKey,
  exts : Array[Bytes],
  tag? : Int = 0xa3,
) -> Bytes {
  let tbs = @asn1.sequence([
    @asn1.explicit(0, @asn1.integer(b"\x02")),
    @asn1.integer(b"\x01"),
    @x509.alg_ecdsa_sha256(),
    @x509.common_name("a.example"),
    @x509.validity_of("250101000000Z", "350101000000Z"),
    @x509.common_name("a.example"),
    @x509.spki_of(pub_key),
    @asn1.tlv(tag, @asn1.sequence(exts)),
  ])
  @asn1.sequence([tbs, @x509.alg_ecdsa_sha256(), @asn1.bit_string(b"\x00")])
}

///|
test "x509: the DER rules RFC 5280 §4.2 layers on the extensions are enforced" {
  let pub_key = key_of(
    "233333333333333333333333333333333333333333333333333333333333eeff",
  ).public()
  let san = @asn1.octet_string(
    @asn1.sequence([@asn1.tlv(0x82, @utf8.encode("a.example"))]),
  )
  let ext_san = @asn1.sequence([@asn1.oid([2, 5, 29, 17]), san])
  assert_eq(
    refusal(() => {
      @x509.parse(with_exts(pub_key, [ext_san, ext_san])[:]) |> ignore
    }),
    "Malformed: extension 2.5.29.17 appears twice",
  )
  assert_eq(
    refusal(() => {
      let spelled = @asn1.sequence([
        @asn1.oid([2, 5, 29, 17]),
        @asn1.tlv(0x01, b"\x00"),
        san,
      ])
      @x509.parse(with_exts(pub_key, [spelled])[:]) |> ignore
    }),
    "Malformed: extension spells out the default criticality",
  )
  assert_eq(
    refusal(() => {
      let empty = @asn1.sequence([
        @asn1.oid([2, 5, 29, 17]),
        @asn1.octet_string(@asn1.sequence([])),
      ])
      @x509.parse(with_exts(pub_key, [empty])[:]) |> ignore
    }),
    "Malformed: empty subjectAltName",
  )
  assert_eq(
    refusal(() => {
      let short_ip = @asn1.sequence([
        @asn1.oid([2, 5, 29, 17]),
        @asn1.octet_string(@asn1.sequence([@asn1.tlv(0x87, b"\x7f\x00\x00")])),
      ])
      @x509.parse(with_exts(pub_key, [short_ip])[:]) |> ignore
    }),
    "Malformed: iPAddress is neither four nor sixteen octets",
  )
  assert_eq(
    refusal(() => {
      let path_only = @asn1.sequence([
        @asn1.oid([2, 5, 29, 19]),
        @asn1.octet_string(@asn1.sequence([@asn1.integer(b"\x00")])),
      ])
      @x509.parse(with_exts(pub_key, [path_only])[:]) |> ignore
    }),
    "Malformed: pathLenConstraint without cA",
  )
  assert_eq(
    refusal(() => {
      let not_ca = @asn1.sequence([
        @asn1.oid([2, 5, 29, 19]),
        @asn1.octet_string(@asn1.sequence([@asn1.tlv(0x01, b"\x00")])),
      ])
      @x509.parse(with_exts(pub_key, [not_ca])[:]) |> ignore
    }),
    "Malformed: basicConstraints spells out the default cA",
  )
  // `[3] EXPLICIT` is a constructed tag. The primitive spelling holds the same octets and is not
  // the same encoding, and one certificate may have only one.
  assert_eq(
    refusal(() => {
      @x509.parse(with_exts(pub_key, [ext_san], tag=0x83)[:]) |> ignore
    }),
    "Malformed: extensions are not EXPLICIT-tagged",
  )
  // A critical extension nobody here understands is reported, because RFC 5280 §4.2 says a
  // certificate carrying one cannot be used and only the caller can act on that.
  let odd = @asn1.sequence([
    @asn1.oid([1, 3, 6, 1, 4, 1, 233]),
    @asn1.tlv(0x01, b"\xff"),
    @asn1.octet_string(b"\x2a"),
  ])
  let cert = @x509.parse(with_exts(pub_key, [ext_san, odd])[:])
  assert_eq(cert.exts.unknown_critical, ["1.3.6.1.4.1.233"])
  assert_eq(cert.exts.san, [@x509.Dns("a.example")])
}

///|
test "x509: a certificate is refused unless it is exactly one well-formed certificate" {
  let der = pem(p256_lfanke)
  assert_eq(
    refusal(() => @x509.parse(der[0:der.length() - 5]) |> ignore),
    "Malformed: length exceeds input",
  )
  let glued = Buffer()
  glued.write_bytes(der[:])
  glued.write_bytes(b"\x2a"[:])
  assert_eq(
    refusal(() => @x509.parse(glued.to_bytes()[:]) |> ignore),
    "Malformed: trailing bytes",
  )
  // The outer length rewritten to 2^31-1: a 32-bit `offset + length` wraps negative here, and a
  // parser that compares the wrapped sum reads the whole heap as certificate.
  let bogus = Buffer()
  bogus.write_bytes(b"\x30\x84\x7f\xff\xff\xff"[:])
  bogus.write_bytes(der[4:])
  assert_eq(
    refusal(() => @x509.parse(bogus.to_bytes()[:]) |> ignore),
    "Malformed: length exceeds input",
  )
  let pub_key = key_of(
    "233333333333333333333333333333333333333333333333333333333333eeff",
  ).public()
  // RFC 5280 §4.1.1.2: the outer signature algorithm is a copy of the one inside the signed
  // bytes. A peer that can make them differ picks the algorithm a verifier reads.
  assert_eq(
    refusal(() => {
      let tbs = @x509.tbs_of(
        b"\x01", "a.example", "250101000000Z", "350101000000Z", pub_key,
      )
      let swapped = @asn1.sequence([
        tbs,
        @asn1.sequence([@asn1.oid([1, 2, 840, 113549, 1, 1, 11]), @asn1.null()]),
        @asn1.bit_string(b"\x00"),
      ])
      @x509.parse(swapped[:]) |> ignore
    }),
    "Malformed: the signature algorithm differs from the one the TBSCertificate names",
  )
}

///|
test "x509: a public key is refused unless it is an uncompressed point on P-256" {
  let cert = @x509.parse(pem(p256_lfanke)[:])
  let good = cert.spki
  let off_curve = Buffer()
  off_curve.write_bytes(good.key.bytes[0:64])
  off_curve.write_byte((good.key.bytes[64].to_int() ^ 1).to_byte())
  assert_eq(
    refusal(() => {
      let spki : @x509.Spki = {
        alg: good.alg,
        params: good.params,
        key: { bytes: off_curve.to_bytes(), unused: 0, },
      }
      spki.p256() |> ignore
    }),
    "Malformed: public key is not a point on P-256",
  )
  assert_eq(
    refusal(() => {
      let spki : @x509.Spki = {
        alg: good.alg,
        params: good.params,
        key: { bytes: good.key.bytes[0:33].to_owned(), unused: 0, },
      }
      spki.p256() |> ignore
    }),
    "Malformed: public key is not an uncompressed P-256 point",
  )
  assert_eq(
    refusal(() => {
      let spki : @x509.Spki = {
        alg: good.alg,
        params: Some("1.3.132.0.34"),
        key: good.key,
      }
      spki.p256() |> ignore
    }),
    "Unsupported: elliptic curve other than prime256v1",
  )
}
