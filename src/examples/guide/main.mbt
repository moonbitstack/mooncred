// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// Every check is made at one moment, 2026-10-29 00:00 UTC, the day after the
/// openssl fixtures were written, so the transcript is the same on every run.
let now : Int64 = 1793232000L

///|
fn sign_one() -> (String, @jwt.Keyed) raise {
  // @@listing sign
  let secret = b"a shared secret nobody else has"
  let key = @jwt.mac(fn() {
    @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
  })
  let claims : Map[String, Json] = {
    "sub": "heke1228",
    "iss": "moonbitstack",
    "aud": "moonapi",
    "exp": 1793235600,
  }
  let token = @jwt.sign(claims, HS256, key)
  println(token)
  let got = @jwt.verify(
    token[:],
    HS256,
    key,
    now=At(now),
    issuer="moonbitstack",
    audience=["moonapi"],
  )
  if got.get("sub") is Some(String(sub)) {
    println("subject: \{sub}")
  }
  // @@end
  (token, key)
}

///|
fn refuse(token : String, key : @jwt.Keyed) -> Unit raise {
  // @@listing refuse
  // The same bytes, offered as another algorithm.
  try @jwt.verify(token[:], HS384, key, now=At(now)) |> ignore catch {
    Algorithm(want~, got~) => println("refused: \{got} is not \{want}")
    _ => println("refused")
  }
  // Two hours on, the token has lapsed.
  try @jwt.verify(token[:], HS256, key, now=At(now + 7200)) |> ignore catch {
    Expired(at~) => println("refused: expired at \{at.to_int64()}")
    _ => println("refused")
  }
  // Read anyway, with the clock switched off on purpose.
  let old = @jwt.verify(token[:], HS256, key, now=Ignored)
  println("read with no clock: \{old.length()} claims")
  // @@end
}

///|
fn settle(token : String, key : @jwt.Keyed) -> Unit raise {
  // @@listing policy
  // Assembled once for a deployment.
  let ours = @jwt.Policy::new(
    issuer="moonbitstack",
    audience=["moonapi"],
    leeway=30,
  )
  // The same record, written as an update of the preset.
  let same : @jwt.Policy = {
    ..@jwt.policy,
    issuer: Some("moonbitstack"),
    audience: ["moonapi"],
    leeway: 30,
  }
  println("same policy: \{ours == same}")
  // A hundred seconds past `exp`: outside the policy's leeway.
  let late : @jwt.Clock = At(1793235700L)
  // This one call allows two minutes; the argument beats the record.
  let got = @jwt.verify(token[:], HS256, key, now=late, policy=ours, leeway=120)
  println("accepted with leeway 120: \{got.length()} claims")
  // `wins=Base` turns that around, and the record's 30 s stands.
  try
    @jwt.verify(
      token[:],
      HS256,
      key,
      now=late,
      policy=ours,
      leeway=120,
      wins=Base,
    )
    |> ignore
  catch {
    Expired(..) => println("refused with wins=Base: the policy decides")
    _ => println("refused")
  }
  // @@end
}

///|
fn keys_from_json() -> Unit raise {
  // @@listing jwk
  let set = @jwk.Set::parse(
    (
      #|{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"2026-09","alg":"EdDSA",
      #|"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
      #|"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}
    ),
  )
  guard set.pick(alg="EdDSA", id="2026-09") is Some(jwk) else { return }
  guard jwk.material() is Okp(x~, secret=Some(seed), ..) else { return }
  let signer = @ed25519.PrivateKey::new(seed[:])
  let token = @jwt.sign({ "sub": "heke1228" }, EdDSA, signer, extra={
    "kid": "2026-09",
  })
  // A verifier reads `kid` first, fetches that key, then verifies.
  guard @jwt.header(token[:]).get("kid") is Some(String(kid)) else { return }
  guard set.by_id(kid) is Some(found) else { return }
  guard found.material() is Okp(x=public, ..) else { return }
  println("kid \{kid}, same key: \{public == x}")
  let got = @jwt.verify(
    token[:],
    EdDSA,
    @ed25519.PublicKey::new(public[:]),
    now=At(now),
  )
  println("EdDSA verified: \{got.length()} claim")
  // @@end
}

///|
fn signed_strings() -> Unit raise {
  // @@listing token
  let keys = @token.Keys::new(b"the key that signs session cookies")
  let cookie = @token.sign(
    b"user=heke1228",
    keys~,
    salt="session",
    at=Some(now),
  )
  println(cookie)
  let value = @token.verify(
    cookie[:],
    keys~,
    salt="session",
    max_age=Some(3600L),
    now~,
  )
  println("value: \{value.length()} bytes")
  // A cookie signed for one purpose does not pass for another.
  try @token.verify(cookie[:], keys~, salt="reset", now~) |> ignore catch {
    Signature => println("refused under salt \"reset\"")
    _ => println("refused")
  }
  // A new key signs from now on; cookies under the old one still read.
  let next = keys.rotate(b"next quarter's session key")
  let kept = @token.verify(cookie[:], keys=next, salt="session", now~)
  println("after rotation: \{kept.length()} bytes")
  // @@end
}

///|
fn chains() -> Unit raise {
  // @@listing chain
  let anchors = @x509.Roots::pem(authority)
  let chain = [@x509.pem(good)]
  let path = @x509.verify(chain[:], anchors, now~, host="leaf.example.com")
  for cert in path {
    println(cert.subject.cn().unwrap_or("?"))
  }
  try
    @x509.verify(chain[:], anchors, now~, host="other.example.com") |> ignore
  catch {
    Host(name) => println("refused: not issued for \{name}")
    _ => println("refused")
  }
  // @@end
}

///|
fn read_one() -> Unit raise {
  // @@listing read
  let cert = @x509.parse(@x509.pem(good))
  println("subject  \{cert.subject.cn().unwrap_or("?")}")
  println("issuer   \{cert.issuer.cn().unwrap_or("?")}")
  for name in cert.exts.san {
    if name is Dns(host) {
      println("dns      \{host}")
    }
  }
  println("serves leaf.example.com: \{cert.matches("leaf.example.com")}")
  println("valid now: \{cert.valid_at(now)}")
  let ca = @x509.parse(@x509.pem(authority))
  println("signed by the CA: \{cert.signed_by(ca.spki)}")
  // @@end
}

///|
fn issue() -> (@ecdsa.PrivateKey, Bytes) raise {
  // @@listing issue
  // RFC 6979's P-256 test key; a real one comes from a random source.
  let key = @ecdsa.PrivateKey::new(
    @base16.decode(
      "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
    ),
  )
  let der = @x509.self_signed(
    key, b"\x01", "moonbitstack.example", "261029000000Z", "271029000000Z",
  )
  let cert = @x509.parse(der)
  println(
    "self-signed \{cert.subject.cn().unwrap_or("?")}: \{cert.signed_by(cert.spki)}",
  )
  // What a CA would ask for instead: a request, signed by the same key.
  let pem = @csr.self_signed_pem(
    Ec(key),
    subject=@x509.common_name("moonbitstack.example"),
  )
  let request = @csr.Request::pem(pem)
  println("request verified: \{request.verified()}")
  println("asks for this key: \{request.asks_for(Ec(key.public()))}")
  // @@end
  (key, der)
}

///|
fn at_rest(key : @ecdsa.PrivateKey) -> Unit raise {
  // @@listing keys
  // Salt and IV are arguments: fresh random bytes in production.
  let pem = @x509.PrivateKey::Ec(key).encrypt_pem(
    passphrase="correct horse",
    salt=b"0123456789abcdef",
    iv=b"fedcba9876543210",
  )
  println(pem.split("\n").next().unwrap_or(""))
  let back = @x509.PrivateKey::pem_encrypted(pem, passphrase="correct horse")
  println(
    "same key: \{back.public() is Ec(public) && public.bytes() == key.public().bytes()}",
  )
  try
    @x509.PrivateKey::pem_encrypted(pem, passphrase="battery staple") |> ignore
  catch {
    _ => println("wrong passphrase: refused")
  }
  // @@end
}

///|
fn container(key : @ecdsa.PrivateKey, der : Bytes) -> Unit raise {
  // @@listing pkcs12
  let pfx = @pkcs12.build(
    certs=[der],
    key=Some(@x509.PrivateKey::Ec(key).pkcs8()),
    passphrase="correct horse",
    salt=b"0123456789abcdef",
    iv=b"fedcba9876543210",
    mac_salt=b"mac salt",
  )
  let read = @pkcs12.parse(pfx)
  println("MAC checks out: \{read.verify(passphrase="correct horse")}")
  let inside = read.contents(passphrase="correct horse")
  println(
    "\{inside.certs.length()} certificate, key inside: \{inside.key is Some(_)}",
  )
  // @@end
}

///|
fn revocation() -> Unit raise {
  // @@listing revoke
  let list = @revoke.Crl::pem(crl)
  let ca = @x509.parse(@x509.pem(authority))
  println("list signed by the CA: \{list.signed_by(ca.spki)}")
  println("list still fresh: \{list.fresh(now)}")
  for name in ["good", "revoked"] {
    let cert = @x509.parse(
      @x509.pem(if name == "good" { good } else { revoked }),
    )
    match list.status(cert) {
      Good => println("\{name}: good")
      Revoked(_) => println("\{name}: revoked")
      Unknown => println("\{name}: unknown")
    }
  }
  // @@end
}

///|
fn encrypted() -> Unit raise {
  // @@listing jwe
  let shared = b"a 32-byte key for A256GCM, here."
  let jwe = @jwe.encrypt(
    b"card ending 4242",
    key=Shared(shared),
    alg=Dir,
    enc=A256Gcm,
    iv=b"twelve bytes",
  )
  println(jwe)
  let opened = @jwe.decrypt(jwe[:], key=Shared(shared), alg=Dir, enc=A256Gcm)
  println("opened: \{opened == b"card ending 4242"}")
  // @@end
}

///|
fn cwt() -> Unit raise {
  // @@listing cose
  // RFC 8032's first Ed25519 test key.
  let signer = @ed25519.PrivateKey::new(
    @base16.decode(
      "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60",
    ),
  )
  let claims = @cose.Claims::new(
    iss="moonbitstack",
    sub="heke1228",
    exp=1793235600L,
  )
  let token = @cose.signed(claims, alg=EdDsa, signer)
  println("a CWT of \{token.length()} bytes")
  let back = @cose.verified(token, alg=EdDsa, signer.public(), now=At(now))
  println("issuer: \{back.iss.unwrap_or("?")}")
  // @@end
}

///|
fn anchors() -> Unit {
  // @@listing roots
  let mozilla = @roots.mozilla()
  println("\{mozilla.length()} anchors, Mozilla store of \{@roots.version}")
  // @@end
}

///|
#coverage.skip
fn main raise {
  println("@@sign")
  let (token, key) = sign_one()
  println("@@refuse")
  refuse(token, key)
  println("@@policy")
  settle(token, key)
  println("@@jwk")
  keys_from_json()
  println("@@token")
  signed_strings()
  println("@@chain")
  chains()
  println("@@read")
  read_one()
  println("@@issue")
  let (ec, der) = issue()
  println("@@keys")
  at_rest(ec)
  println("@@pkcs12")
  container(ec, der)
  println("@@revoke")
  revocation()
  println("@@jwe")
  encrypted()
  println("@@cose")
  cwt()
  println("@@roots")
  anchors()
}
