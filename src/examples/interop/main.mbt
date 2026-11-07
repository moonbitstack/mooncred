// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What this library writes, for another implementation to read. `scripts/gen_jose_vectors.py`
// runs this program, hands the tokens to go-jose, and records what go-jose made of them beside
// the tokens go-jose wrote; the tests then replay both halves. Every parameter that would be
// random is pinned, so the tokens are the same on every run and can be committed.

///|
fn octets(hex : String) -> Bytes {
  @base16.decode(hex) catch {
    _ => abort("hex")
  }
}

///|
fn mac(secret : Bytes) -> &@spec.Signer {
  (
    @jwt.mac(fn() { @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() }) }) :
    &@spec.Signer)
}

///|
fn main raise {
  let report : Map[String, Json] = Map([])
  let payload = @utf8.encode("{\"iss\":\"moonbitstack\"}")
  let hmac_key = octets(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  )
  // The point of the curve at scalar one, so the key is short enough to read.
  let ec = @ecdsa.PrivateKey::with_hash(
    octets("0000000000000000000000000000000000000000000000000000000000000001"),
    fn() { @sha2.Hasher::new() },
  ) catch {
    _ => abort("a scalar")
  }
  report["jws-hs256"] = Json::string(
    @jwt.sign_bytes(payload, HS256, mac(hmac_key)),
  )
  report["jws-b64-false"] = Json::string(
    @jwt.sign_bytes(b"$.02", HS256, mac(hmac_key), b64=false, detached=true),
  )
  report["jws-es256-flat"] = Json::string(
    @json.dumps(
      @jwt.Message::new(payload).sign(ES256, (ec : &@spec.Signer)).flattened(),
    ),
  )
  let plain = @utf8.encode("interop payload")
  let kek128 = octets("404142434445464748494a4b4c4d4e4f")
  let kek256 = octets(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  )
  let content128 = octets("000102030405060708090a0b0c0d0e0f")
  let iv12 = octets("000102030405060708090a0b")
  report["jwe-dir-compact"] = Json::string(
    @jwe.encrypt(
      plain,
      key=@jwe.Key::Shared(content128),
      alg=@jwe.Alg::Dir,
      enc=@jwe.Enc::A128Gcm,
      iv=iv12[:],
    ),
  )
  report["jwe-a128kw-compact"] = Json::string(
    @jwe.encrypt(
      plain,
      key=@jwe.Key::Shared(kek128),
      alg=@jwe.Alg::A128Kw,
      enc=@jwe.Enc::A128Gcm,
      cek=content128,
      iv=iv12[:],
    ),
  )
  report["jwe-gcmkw-compact"] = Json::string(
    @jwe.encrypt(
      plain,
      key=@jwe.Key::Shared(kek256),
      alg=@jwe.Alg::A256GcmKw,
      enc=@jwe.Enc::A128Gcm,
      cek=content128,
      iv=iv12[:],
      wrap_iv=octets("101112131415161718191a1b"),
    ),
  )
  report["jwe-pbes2-compact"] = Json::string(
    @jwe.encrypt(
      plain,
      key=@jwe.Key::Password(b"correct horse battery staple"),
      alg=@jwe.Alg::Pbes2Hs256A128Kw,
      enc=@jwe.Enc::A128Gcm,
      cek=content128,
      iv=iv12[:],
      salt=octets("f0e1d2c3b4a5968778695a4b3c2d1e0f"),
      count=2048,
    ),
  )
  let peer = @ecdsa.PrivateKey::with_hash(
    octets("0000000000000000000000000000000000000000000000000000000000000003"),
    fn() { @sha2.Hasher::new() },
  ) catch {
    _ => abort("a scalar")
  }
  report["jwe-ecdh-kw-compact"] = Json::string(
    @jwe.encrypt(
      plain,
      key=@jwe.Key::Agreement(P256, peer.public().bytes()),
      alg=@jwe.Alg::EcdhEsA128Kw,
      enc=@jwe.Enc::A128Gcm,
      cek=content128,
      iv=iv12[:],
      ephemeral=octets(
        "0000000000000000000000000000000000000000000000000000000000000005",
      ),
    ),
  )
  let aad = @utf8.encode("[\"interop\",1]")
  report["jwe-a128kw-json-aad"] = Json::string(
    @json.dumps(
      @jwe.seal(
        plain,
        enc=@jwe.Enc::A128Gcm,
        recipients=[
          {
            ..@jwe.Recipient::new(@jwe.Alg::A128Kw, @jwe.Key::Shared(kek128)),
            cek: Some(content128),
            header: kid_header("interop"),
          },
        ],
        iv=iv12[:],
        aad~,
      ),
    ),
  )
  println(@json.dumps(Json::object(report)))
}

///|
fn kid_header(kid : String) -> Map[String, Json] {
  let out : Map[String, Json] = Map([])
  out["kid"] = Json::string(kid)
  out
}
