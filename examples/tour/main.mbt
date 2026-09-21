// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A token issued and checked twice over — once with a shared secret, once with
/// a key pair read out of a JWK.
///
///     moon run examples/tour
#coverage.skip
fn main raise {
  let claims : Map[String, Json] = Map([])
  claims["sub"] = Json::string("heke1228")
  claims["iss"] = Json::string("moonbitstack")
  claims["aud"] = Json::string("moonapi")
  claims["exp"] = Json::number(4102444800.0, repr="4102444800")
  claims["scope"] = Json::string("read write")
  let now = 1758412800L

  // HS256: one shared secret signs and verifies.
  let secret = b"a shared secret nobody else has"
  let hs = @jwt.mac(fn() {
    @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
  })
  let token = @jwt.sign(claims, HS256, hs)
  println("HS256 token   -> \{token}")
  let got = @jwt.verify(
    token[:],
    HS256,
    hs,
    now~,
    issuer=Some("moonbitstack"),
    audience=Some("moonapi"),
  )
  println("HS256 subject -> \{@json.write(got.get("sub").unwrap())}")

  // The attack this refuses: the same bytes, read as another algorithm.
  try @jwt.verify(token[:], HS384, hs, now~) |> ignore catch {
    Algorithm(want~, got~) =>
      println("confusion     -> refused: \{got} is not \{want}")
    _ => println("confusion     -> refused")
  } noraise {
    _ => println("confusion     -> accepted, which would be the bug")
  }

  // EdDSA, with the key read from a JWK as a server would read it.
  let key = @jwk.Jwk::parse(
    "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"2026-09\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
  )
  match key.material() {
    Okp(x~, secret=Some(seed), ..) => {
      let sk = @ed25519.PrivateKey::new(seed[:])
      let named : Map[String, Json] = Map([])
      named["kid"] = Json::string(key.id().unwrap())
      let signed = @jwt.sign(claims, EdDSA, sk, extra=named)
      println("EdDSA token   -> \{signed}")
      // A verifier reads `kid` first, then fetches the key, then verifies.
      println(
        "kid           -> \{@json.write(@jwt.header(signed[:]).get("kid").unwrap())}",
      )
      let pk = @ed25519.PublicKey::new(x[:])
      @jwt.verify(signed[:], EdDSA, pk, now~) |> ignore
      println("EdDSA ok      -> true")
      // What a key set may be published as: the public half only.
      println("published     -> \{@json.write(key.json())}")
    }
    _ => println("the JWK did not carry an Ed25519 key pair")
  }
}
