// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
fn sha(bits : Int) -> () -> &@spec.Hash {
  match bits {
    384 => fn() { @sha2.Hasher::new(kind=Sha384) }
    512 => fn() { @sha2.Hasher::new(kind=Sha512) }
    _ => fn() { @sha2.Hasher::new() }
  }
}

///|
/// The key material behind every vector below, as a third-party library wrote
/// it out.
let secret : String = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

///|
let rsa_n : String = "acecf7fefc93a78e2b245e09d20d3d52ed106b7176dc698915f755d2ad0402043ec7dd0b8594b60039639b85023c58d269218ce8acaef26a9743190d9edbbc4feb13944cf9600d6de2dd92ee18f6780f2a5ff0a9555a6b75c5f60137695d7aa3dcd3dbf98d76473031e045300dba8a1a8a1fd3da2476fa2863f065827dba1e1dc7796ac55b4184c54ed7fa1eb85503fe6142120a66bdcb45a77b49d5b6d4c31dff565bb73b41dd7cc84f26d17a4e4dc1b35503f05816c0e30a84005497221511545686b715cca9801c8b516aafe5633ea801be09d330fe60fea7bb357f37f3ec082a67c213c9c1dee0fe0fe692344827eaa5b22d97e6ee75c4dc4fe2ec082bbd"

///|
let rsa_e : String = "010001"

///|
let rsa_d : String = "1997fe117d890e0aceec5445c052c8d181f844eab774a263117ef8b3147bec1f7c3a410750474513adeac5ed0efa670c0756d99fe35506588bd838b8491b8d18c7fa6f1fe065dcbef78da34e3da016ff699e67046cf753c1cbe19fe6f75f884401ee5257b25dffe5cc6ffcd582a6aa03890f725fce3754c98f1718b312502e5e2c10fbd41eb86e2b1dcd67405bc91ab896e0cb67cfb153873cd1d8f67816cef8cf0b4a8eff6bb5e97fec3f2fadf0002ab0321a2e90b425f98d1beca9080f01ac880f300d92c5816e8fd88f4fa61a9329af416fe203e8e45ce8fd5b177b141b4d242cf9fbc5d5734f88a45a8ccec1238493728afda3a111700b17f93a953046a1"

///|
let p256_point : String = "04f3bcd9e200a6aef94fe2b044e9530c32cd2914cba8b917d7f1f05f7c66cda6b03f4d68e8cfd5141e7fc963e7af60d64504b0a165d841d2703daa7d6847377f62"

///|
let p256_d : String = "73a136f76f118da7cc610a07d1b1961901dc883eaf3b173ed80d8bd9400f5fb0"

///|
let p384_point : String = "044e0a3c7590949ddeff266a97952603c87dcf0509d4eed21fbeb3c4c1a103c0c6fb01cb37ca93a567ea9a19bb7a8403ae56cdb62a444d87039083c553ca152b1ec6f17ad6807e8f17672deca71d578032dbcb725a4053beb1079e2cd2e8e18411"

///|
let p384_d : String = "7f77765c43c41514c39b7b52bc9b95e9d9c4f1e0ca15420f033ddc646cbc69c9518d60dfe0929733f4130beb00bba0b3"

///|
let p521_point : String = "040106c39bc0409afc9a7b3ec8231ed22f65ecdd3614d78c5e7e8cce3a0dc36af1c026b77a4a8108f4557f3cd3911db743de7ea77fe6c1b2fff988dba0b1570a237b8a01be80b0b6cdf8feab186ce85372660e2fe3cbaced5099c81c24922f14ed86d3599d4e9b5b8ec5fe8fc2d1cbe847c2cfef686397c398a77a040a87b92af9228a2e33"

///|
let p521_d : String = "0168d0bb45c97c6fa680f16f396afca7f438dc0ffe876073e9087ecc36b3204cb12eb26aee5f19753dbae5e97d208e9397e3ba824e03c50ae0141950fbc6c9043c05"

///|
let ed_public : String = "50201ea15627d2b5e2683619a1ddf0c65239d6327a6c20458be6e55dbf29abe5"

///|
let ed_seed : String = "be664b2678529bf1f15b69e8c5238b378b60f6c59069848da57fd857eaa82b29"

///|
/// The claims every vector carries, in the order they were signed in.
fn claims() -> Map[String, Json] {
  let out : Map[String, Json] = Map([])
  out["sub"] = Json::string("1234567890")
  out["iss"] = Json::string("moonbitstack")
  out["aud"] = Json::string("moonapi")
  out["exp"] = Json::number(4102444800.0, repr="4102444800")
  out["nbf"] = Json::number(1600000000.0, repr="1600000000")
  out["scope"] = Json::string("read write")
  out
}

///|
/// The signer for an algorithm, built from the material above.
fn signer(alg : @jwt.Alg) -> &@spec.Signer raise {
  match alg {
    HS256 => return @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
    HS384 => return @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(384)) })
    HS512 => return @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(512)) })
    RS256 => return rsa_key(Sha256, Pkcs1)
    RS384 => return rsa_key(Sha384, Pkcs1)
    RS512 => return rsa_key(Sha512, Pkcs1)
    PS256 => return rsa_key(Sha256, Pss(salt=32))
    PS384 => return rsa_key(Sha384, Pss(salt=48))
    PS512 => return rsa_key(Sha512, Pss(salt=64))
    ES256 => return ec_key(P256, p256_d)
    ES384 => return ec_key(P384, p384_d)
    ES512 => return ec_key(P521, p521_d)
    EdDSA => return @ed25519.PrivateKey::new(raw(ed_seed)[:])
  }
}

///|
/// The matching verifier.
fn verifier(alg : @jwt.Alg) -> &@spec.Verifier raise {
  match alg {
    HS256 => return @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
    HS384 => return @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(384)) })
    HS512 => return @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(512)) })
    RS256 => return rsa_public(Sha256, Pkcs1)
    RS384 => return rsa_public(Sha384, Pkcs1)
    RS512 => return rsa_public(Sha512, Pkcs1)
    PS256 => return rsa_public(Sha256, Pss(salt=32))
    PS384 => return rsa_public(Sha384, Pss(salt=48))
    PS512 => return rsa_public(Sha512, Pss(salt=64))
    ES256 => return ec_public(P256, p256_point)
    ES384 => return ec_public(P384, p384_point)
    ES512 => return ec_public(P521, p521_point)
    EdDSA => return @ed25519.PublicKey::new(raw(ed_public)[:])
  }
}

///|
fn rsa_key(digest : @rsa.Digest, scheme : @rsa.Scheme) -> @rsa.PrivateKey raise {
  @rsa.PrivateKey::new(
    raw(rsa_n)[:],
    raw(rsa_e)[:],
    raw(rsa_d)[:],
    digest~,
    scheme~,
  )
}

///|
fn rsa_public(
  digest : @rsa.Digest,
  scheme : @rsa.Scheme,
) -> @rsa.PublicKey raise {
  @rsa.PublicKey::new(raw(rsa_n)[:], raw(rsa_e)[:], digest~, scheme~)
}

///|
fn ec_key(curve : @ecdsa.Curve, d : String) -> @ecdsa.PrivateKey raise {
  @ecdsa.PrivateKey::new(raw(d)[:], curve~)
}

///|
fn ec_public(curve : @ecdsa.Curve, point : String) -> @ecdsa.PublicKey raise {
  @ecdsa.PublicKey::new(raw(point)[:], curve~)
}

///|
/// A token for each of the thirteen algorithms, signed by a third-party
/// library. The deterministic ones must be reproduced byte for byte; ES* and
/// PS* draw a random nonce or salt, so those can only be verified.
test "every JOSE algorithm against a third-party signer" {
  let cases = [
    (
      "HS256", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.hafw7zlQiWJt6Qp89S8rpOZd65QI42WCiCOWMmocrLo",
      true,
    ),
    (
      "HS384", "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.5osDbN8RZ6Pr813QhhbFEl8eBGb2knPgG2To6tYi45n9k9oRwXAnB0q_TwjpKU95",
      true,
    ),
    (
      "HS512", "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.DTI-43Dqp_3zU7W2RwhQgZTrbe9N33K3yM1dmSxQf6t2BVPUxpefLriwOMMWzxRfBQQQLvhV_ptyXqux3q_p1w",
      true,
    ),
    (
      "RS256", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.cDg5BPaiKAXkWvsIZ5kqG8_coXIg1HdLnZJhtm72ticjCa4EDaweO1f23U11tOWslIBNfoiQwoUjTPIzH95dcqXK0WSAQFKwaafTnsd2N_TJb7G5FMFkvUwugX3T5k_tLC0o-yqZDEFySyBQbsGj9Z-IE_lMJeRWrv5XIyFX-46cRdfpHu3DWHIO6suJfUq7WxE3klUD0t4Pxr0ACHcj3XnlwdHeLio73QCMu6BEjP-wa9UJ0ME1jYjQMy9oKCtR9xekuwniOWGQsQUPiPxcqqkmIheDkGIjtvCmIjlqXgDlJ16S3GGx6lzAQBu8rdMLlJsacwNIO6F2Gz4LGS6ySQ",
      true,
    ),
    (
      "RS384", "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.MvtxOhDThi49pfpayQlljek5sryFk9WWBMEf4h-ERpjDLQyX4jNUSbOeN5Q9X9XfLOIrHuMjmZUQZywqb6hckpApA-_smYxrlcgw2MyqkMtWmWdf2ZrKsP1thFOew-TFwaNUZO6JLdCD2xUOb4B7r7E28QhmmgGWYcGMUIO7uKnp1MdGndfPkdLyHPycx7c_mHrL5VbWqhmWEYLs9Vq5H8tiOPeE6398OaC0FoF5KeajCrvLPS3EpnWyb-qfBbtBk_cror2y_SHZmMhdVvq1H-82SJQsLFHI3L1EphC34XO9nOsxjQXNk8-iHaX9BBALE_QjdmEy3UMn6Gt9KuoaZg",
      true,
    ),
    (
      "RS512", "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.i1NT52dMgjd9krRsXShoGUbGQlukKolwxyZ_IAUGXF8cmPRNjkMPnO66TCqO7qPN419U3Ek4bRzwpjsrUJbKHQdFRVAnWoqfv498dLDX9H16iRkquD2k1rCq4hWATVSFvemdkSfIab-DKgCwvKmysyZUPcWaVfy8PeLxF-n3pVYj78Yw1giz4XwxqSSvjU27mZOZzOX33OVADnFxh0rQJcIl_lMSPBAbPpBIMIQDSKcDya2sFWvG_pNa1E7H-oe9tLGQMmApXx8R2TqLULzlBt-qjJZ-gMCZFmWvt-UavAi_LV55ekOzOrUwZLb29BJYXG1LmvxhLr9v-KB12_Q8Kw",
      true,
    ),
    (
      "PS256", "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.AfpTgzn_oMmHQmU08IilfHDPMr09aFB1akKcOF0B0hUMWJFUfWHnquaDs7n4zliQU8DuwszYOaLL4Hk-gVkVtaX_9yY8SWHA_VSa1VqHGML3YDsKe8TxQnBk95Zm2E_cOdiMLCHOR0DioiL8PIML4zX1Hb5yCx0YRvRhqflCVIfkikpRRCRRlf4B7iQh15MzaG4HFbTtYFPv3gO9ctJbkOrnnf-q4Eoy_S-r_L32n7YykoNmyuPsVcG9oLRgkiljIp0B0v9g0GjrT8409PTwM4KE3Wq65LZRXS6Ss9l698ZW7ol3gBsaQsT2IJs1jYoyJMxL-8O3AxRlVRRKTbjF9w",
      false,
    ),
    (
      "PS384", "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.HN2GvNX4QYptB8cAICmMyz5C2DxZhJzG5_s1aSzRrA1VamdpH810Zu_VTtJbo8qm7gmscHHFZWPbT32Gzw8rWGDNKhzc__GOT0hIXeg7gAKODRxA3U7Kajq9QJFPEjGf-ugGCq797XhlJCv5eaLI73S1sdapOgIOVJiHWarqlDk6HBZdjwzXPHzK8wFPRO9gogFT4jqiHNw8cl404aRYc61cn-8SfenEijcVLGczFHQjh1kxxpY4yBoBrVStJ6WCiMvvSl8GBmQPkUlxtWgs-pESPiNJonZvRwks6tFROq-zyXzTkhw4N7R0cJBeAxI8-gIQG8J-c931meQXlJoQMg",
      false,
    ),
    (
      "PS512", "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.eLN6fsowiXb8fPEYDbJwk9nsChoA8zoBQWhEGD95vacqv_vO2OajpwBMK-blJP21veKHTBW9v3kF57oj-cXIc6fj0yV4_7yURE9p4iu5cAZSP5pChJDDg8VPHpOBxdORVlqp55kDgKVXQXy8Sx7yZB4GrGJSR8E-E4mELB3uQEpuM7_d7lKt0dqBGU7hT7tImNHuF_Jrl7RyCqBNVQ8_HuPyqnWbollUrnaaqUQtfnKbvkgi-eWJpxZGkcONUaT444ol4lENOlSPmgmf5se550xim3UxlIJSB8uY2LJLuW9LvdY9IMLiJGwELquFQeaPGrkIQ1rjLbmdL6CLfODjkA",
      false,
    ),
    (
      "ES256", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.y5bDaDEbiZlkw0tvTy5dnce4G38qzxSD8hrglNkVhR97_zUVx2KShIzjo69K3Vc2wdDJF_BSTRvqL-sACwkIxQ",
      false,
    ),
    (
      "ES384", "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.Th6uv-kESRKC1AZYbiuOq6GOAoxqnjwhj9Y4ACeJIkX0_wx4UPqyQr29PwxrWRBNYlvWAcvnSREb8THLDV4dIpJEU46xVvfAcyabhj91vPID90JR7SvTFh-zv5sNvAe-",
      false,
    ),
    (
      "ES512", "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.AIhJE7MCkmi5cqHTeilaND5Y7hF-ZjlsEV7qsZIKWEVKUsyxo8aifW_yodTBFwcKG02s-w7-HylxCT1EW5QLAN1jAE6AMSDRvYkK5PhqGkT1uUenxpd0nT04VAjhNQAZDZStMtlZvj5CXhYtrVwWM9RX7V0tQlD3zwxhiHGkYdniXb64",
      false,
    ),
    (
      "EdDSA", "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoibW9vbmJpdHN0YWNrIiwiYXVkIjoibW9vbmFwaSIsImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNjAwMDAwMDAwLCJzY29wZSI6InJlYWQgd3JpdGUifQ.9H5IBsaTipPjGcqfD_vnXDpfvl3PBCoN9-iDyVQNyRndUDNg6x2nROlAdKV_kuQDfH3QIQKdnRf1DQDP4clsBg",
      true,
    ),
  ]
  for case in cases {
    let (name, token, exact) = case
    let alg = @jwt.Alg::of(name[:])
    let got = @jwt.verify(token[:], alg, verifier(alg), now=At(1700000000L))
    assert_eq(got.get("sub"), Some(Json::string("1234567890")))
    assert_eq(got.get("scope"), Some(Json::string("read write")))
    if exact {
      assert_eq(@jwt.sign(claims(), alg, signer(alg)), token)
    }
    // Ours must verify under theirs' key either way.
    let ours = @jwt.sign(claims(), alg, signer(alg))
    @jwt.verify(ours[:], alg, verifier(alg), now=At(1700000000L)) |> ignore
  }
}

///|
/// RFC 7515 §A.1's worked example, verified exactly as it is printed — header
/// bytes, line breaks and all. Our own signer writes a different header, so this
/// is a verification vector and not a signing one.
test "the RFC 7515 A.1 example" {
  let key = @base64.decode(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    kind=Url,
  )
  let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(key[:], sha(256)) })
  // The token expired in 2011, so it is read at a time when it had not.
  let got = @jwt.verify(token[:], HS256, hs, now=At(1300000000L))
  assert_eq(got.get("iss"), Some(Json::string("joe")))
  assert_eq(got.get("http://example.com/is_root"), Some(Json::boolean(true)))
  // And it is expired now, which is what the claim is for.
  try @jwt.verify(token[:], HS256, hs, now=At(1700000000L)) |> ignore catch {
    e => assert_eq(e, @jwt.Expired(at=1300819380.0))
  } noraise {
    _ => fail("an expired token was accepted")
  }
}

///|
/// The attack this library exists to refuse: a token whose header names an
/// algorithm the verifier did not choose. `alg: none`, and an RSA public key
/// offered as an HMAC secret, are the two famous shapes of it.
test "the algorithm is the verifier's, not the token's" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = @jwt.sign(claims(), HS256, hs)
  // The same bytes, read as a different algorithm.
  try @jwt.verify(token[:], HS384, hs, now=At(1700000000L)) |> ignore catch {
    e => assert_eq(e, @jwt.Algorithm(want="HS384", got="HS256"))
  } noraise {
    _ => fail("HS256 was accepted as HS384")
  }
  // A token built with `alg: none` and no signature at all.
  let head = @base64.encode(
    b"{\"alg\":\"none\",\"typ\":\"JWT\"}"[:],
    kind=Url,
    padding=false,
  )
  let body = @base64.encode(b"{\"sub\":\"admin\"}"[:], kind=Url, padding=false)
  let forged = head + "." + body + "."
  try @jwt.verify(forged[:], HS256, hs, now=At(1700000000L)) |> ignore catch {
    e => assert_true(e is @jwt.Shape(_) || e is @jwt.Algorithm(_))
  } noraise {
    _ => fail("a token with no signature was accepted")
  }
  // `Alg::of` has no name for it either.
  try @jwt.Alg::of("none") |> ignore catch {
    _ => ()
  } noraise {
    _ => fail("`none` was read as an algorithm")
  }
}

///|
/// A signature that does not match, and a body changed after signing.
test "a tampered token is refused" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = @jwt.sign(claims(), HS256, hs)
  let cut = token.rev_find(".").unwrap()
  let bent = token[0:cut].to_owned() + ".AAAA"
  try @jwt.verify(bent[:], HS256, hs, now=At(1700000000L)) |> ignore catch {
    e => assert_eq(e, @jwt.Signature)
  } noraise {
    _ => fail("a replaced signature was accepted")
  }
  // A different key does not verify what this one signed.
  let other = @jwt.mac(fn() { @hmac.Hmac::new(b"wrong"[:], sha(256)) })
  try @jwt.verify(token[:], HS256, other, now=At(1700000000L)) |> ignore catch {
    e => assert_eq(e, @jwt.Signature)
  } noraise {
    _ => fail("another key verified the token")
  }
}

///|
/// The time claims, at the edges: a token expires at `exp`, not after it, and
/// `leeway` moves both edges by the clocks' disagreement.
test "expiry and not-before" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let timed : Map[String, Json] = Map([])
  timed["exp"] = Json::number(2000.0, repr="2000")
  timed["nbf"] = Json::number(1000.0, repr="1000")
  let token = @jwt.sign(timed, HS256, hs)
  @jwt.verify(token[:], HS256, hs, now=At(1500L)) |> ignore
  @jwt.verify(token[:], HS256, hs, now=At(1000L)) |> ignore
  @jwt.verify(token[:], HS256, hs, now=At(1999L)) |> ignore
  try @jwt.verify(token[:], HS256, hs, now=At(2000L)) |> ignore catch {
    e => assert_eq(e, @jwt.Expired(at=2000.0))
  } noraise {
    _ => fail("a token was accepted at the second it expired")
  }
  try @jwt.verify(token[:], HS256, hs, now=At(999L)) |> ignore catch {
    e => assert_eq(e, @jwt.TooEarly(at=1000.0))
  } noraise {
    _ => fail("a token was accepted before it began")
  }
  // Leeway widens both edges and nothing else.
  @jwt.verify(token[:], HS256, hs, now=At(2030L), leeway=60L) |> ignore
  @jwt.verify(token[:], HS256, hs, now=At(950L), leeway=60L) |> ignore
  // A token with neither claim never expires, which is the caller's problem.
  let forever = @jwt.sign(Map([]), HS256, hs)
  @jwt.verify(forever[:], HS256, hs, now=At(99999999L)) |> ignore
}

///|
/// `iss` and `aud`, checked only when the caller names them.
test "issuer and audience" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = @jwt.sign(claims(), HS256, hs)
  @jwt.verify(token[:], HS256, hs, now=At(1700000000L), issuer="moonbitstack", audience=[
    "moonapi",
  ])
  |> ignore
  try
    @jwt.verify(token[:], HS256, hs, now=At(1700000000L), issuer="someone")
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Issuer(want="someone", got="moonbitstack"))
  } noraise {
    _ => fail("a token from the wrong issuer was accepted")
  }
  try
    @jwt.verify(token[:], HS256, hs, now=At(1700000000L), audience=["elsewhere"])
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Audience(want=["elsewhere"]))
  } noraise {
    _ => fail("a token for another audience was accepted")
  }
  // `aud` may be a list, and then membership is what counts.
  let many : Map[String, Json] = Map([])
  many["aud"] = Json::array([Json::string("a"), Json::string("b")])
  let list = @jwt.sign(many, HS256, hs)
  @jwt.verify(list[:], HS256, hs, now=At(0L), audience=["b"]) |> ignore
  try
    @jwt.verify(list[:], HS256, hs, now=At(0L), audience=["c"]) |> ignore
  catch {
    e => assert_eq(e, @jwt.Audience(want=["c"]))
  } noraise {
    _ => fail("a token for another audience was accepted")
  }
}

///|
/// Everything that is not a token.
test "a malformed token is refused" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let bad = [
    "", ".", "..", "a.b", "a.b.c.d", ".b.c", "a..c", "a.b.", "!!!.eyJhIjoxfQ.sig",
    "eyJhbGciOiJIUzI1NiJ9.!!!.sig",
  ]
  for text in bad {
    try @jwt.verify(text[:], HS256, hs, now=At(0L)) |> ignore catch {
      _ => ()
    } noraise {
      _ => fail("\{text} was read as a token")
    }
  }
  // A header that decodes but is not an object.
  let head = @base64.encode(b"[1]"[:], kind=Url, padding=false)
  let token = head + ".eyJhIjoxfQ.sig"
  try @jwt.verify(token[:], HS256, hs, now=At(0L)) |> ignore catch {
    e => assert_true(e is @jwt.Shape(_))
  } noraise {
    _ => fail("a header that is not an object was accepted")
  }
}

///|
/// Reading the header before choosing a key, which is what `kid` is for.
test "the header can be read before the key is chosen" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let extra : Map[String, Json] = Map([])
  extra["kid"] = Json::string("2026-09")
  let token = @jwt.sign(claims(), HS256, hs, extra~)
  let head = @jwt.header(token[:])
  assert_eq(head.get("kid"), Some(Json::string("2026-09")))
  assert_eq(head.get("alg"), Some(Json::string("HS256")))
  assert_eq(head.get("typ"), Some(Json::string("JWT")))
  // And the claims, with the warning that goes with them.
  assert_eq(
    @jwt.claims_unverified(token[:]).get("sub"),
    Some(Json::string("1234567890")),
  )
}

///|
/// Every check is a named argument, and the defaults are what the mainstream
/// libraries do. This pins each one, in both positions.
test "every check is a knob" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let timed : Map[String, Json] = Map([])
  timed["exp"] = Json::number(2000.0, repr="2000")
  timed["nbf"] = Json::number(1000.0, repr="1000")
  timed["iat"] = Json::number(1000.0, repr="1000")
  timed["iss"] = Json::string("moonbitstack")
  timed["aud"] = Json::string("moonapi")
  timed["sub"] = Json::string("heke1228")
  let token = @jwt.sign(timed, HS256, hs)

  // The hard decode: read a token without asking whether it has expired.
  // Default refuses; `Ignored` is how a caller says otherwise, in writing.
  try @jwt.verify(token[:], HS256, hs, now=At(9999L)) |> ignore catch {
    e => assert_eq(e, @jwt.Expired(at=2000.0))
  } noraise {
    _ => fail("an expired token was accepted by default")
  }
  assert_eq(
    @jwt.verify(token[:], HS256, hs, now=Ignored).get("sub"),
    Some(Json::string("heke1228")),
  )
  // And the same with the two checks turned off one at a time.
  @jwt.verify(token[:], HS256, hs, now=At(9999L), expiry=false) |> ignore
  @jwt.verify(
    token[:],
    HS256,
    hs,
    now=At(0L),
    policy=@jwt.Policy::new(not_before=false),
  )
  |> ignore

  // `iat` is not checked by default — a token issued a second into the future
  // by a fast clock is not an attack, and no mainstream library refuses it.
  @jwt.verify(
    token[:],
    HS256,
    hs,
    now=At(500L),
    policy=@jwt.Policy::new(not_before=false),
  )
  |> ignore
  try
    @jwt.verify(
      token[:],
      HS256,
      hs,
      now=At(500L),
      policy=@jwt.Policy::new(not_before=false, issued_at=true),
    )
    |> ignore
  catch {
    e => assert_eq(e, @jwt.IssuedAt(at=1000.0))
  } noraise {
    _ => fail("`iat` in the future was accepted with the check on")
  }

  // `sub`, checked only when the caller says what to expect.
  @jwt.verify(
    token[:],
    HS256,
    hs,
    now=Ignored,
    policy=@jwt.Policy::new(subject=Some("heke1228")),
  )
  |> ignore
  try
    @jwt.verify(
      token[:],
      HS256,
      hs,
      now=Ignored,
      policy=@jwt.Policy::new(subject=Some("somebody")),
    )
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Subject(want="somebody", got="heke1228"))
  } noraise {
    _ => fail("another subject was accepted")
  }

  // Several audiences: one deployment behind several names is ordinary.
  @jwt.verify(token[:], HS256, hs, now=Ignored, audience=["other", "moonapi"])
  |> ignore
  try
    @jwt.verify(token[:], HS256, hs, now=Ignored, audience=["a", "b"]) |> ignore
  catch {
    e => assert_eq(e, @jwt.Audience(want=["a", "b"]))
  } noraise {
    _ => fail("a token for another audience was accepted")
  }

  // Claims the caller requires. RFC 7519 makes none mandatory, so this is empty
  // by default.
  @jwt.verify(
    token[:],
    HS256,
    hs,
    now=Ignored,
    policy=@jwt.Policy::new(required=["sub", "iss"]),
  )
  |> ignore
  try
    @jwt.verify(
      token[:],
      HS256,
      hs,
      now=Ignored,
      policy=@jwt.Policy::new(required=["jti"]),
    )
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Missing(claim="jti"))
  } noraise {
    _ => fail("a missing required claim was accepted")
  }
}

///|
/// The header's `typ`: written by default because every library writes it,
/// omitted or replaced on request, and checked only when the caller names one.
test "the typ header is a knob at both ends" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = @jwt.sign(claims(), HS256, hs)
  assert_eq(@jwt.header(token[:]).get("typ"), Some(Json::string("JWT")))
  @jwt.verify(
    token[:],
    HS256,
    hs,
    now=Ignored,
    policy=@jwt.Policy::new(typ=Some("jwt")),
  )
  |> ignore
  try
    @jwt.verify(
      token[:],
      HS256,
      hs,
      now=Ignored,
      policy=@jwt.Policy::new(typ=Some("at+jwt")),
    )
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Type(want="at+jwt", got="JWT"))
  } noraise {
    _ => fail("the wrong typ was accepted")
  }
  // RFC 9068's access tokens.
  let access = @jwt.sign(claims(), HS256, hs, typ=Some("at+jwt"))
  assert_eq(@jwt.header(access[:]).get("typ"), Some(Json::string("at+jwt")))
  @jwt.verify(
    access[:],
    HS256,
    hs,
    now=Ignored,
    policy=@jwt.Policy::new(typ=Some("at+jwt")),
  )
  |> ignore
  // And a header with no `typ` at all, which RFC 7519 §5.1 permits.
  let bare = @jwt.sign(claims(), HS256, hs, typ=None)
  assert_eq(@jwt.header(bare[:]).get("typ"), None)
  @jwt.verify(bare[:], HS256, hs, now=Ignored) |> ignore
  try
    @jwt.verify(
      bare[:],
      HS256,
      hs,
      now=Ignored,
      policy=@jwt.Policy::new(typ=Some("JWT")),
    )
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Type(want="JWT", got="none given"))
  } noraise {
    _ => fail("a missing typ passed a check for one")
  }
}

///|
/// An expired token, for the precedence tests below.
fn stale(hs : @jwt.Keyed) -> String {
  let old : Map[String, Json] = Map([])
  old["sub"] = Json::string("heke1228")
  old["exp"] = Json::number(1000.0, repr="1000")
  @jwt.sign(old, HS256, hs)
}

///|
/// Three ways to say the same thing, and they must say the same thing: the
/// constructor, the record update, and the per-call arguments.
test "the three forms agree" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let built = @jwt.Policy::new(leeway=60L, expiry=false)
  let updated : @jwt.Policy = { ..@jwt.policy, leeway: 60L, expiry: false, }
  assert_eq(built, updated)
  let token = stale(hs)
  let by_record = @jwt.verify(token[:], HS256, hs, now=At(9999L), policy=built)
  let by_params = @jwt.verify(
    token[:],
    HS256,
    hs,
    now=At(9999L),
    leeway=60L,
    expiry=false,
  )
  assert_eq(by_record, by_params)
}

///|
/// The published precedence, and the switch that turns it around.
///
/// The default is that the per-call argument wins, because it is the more
/// specific of the two — the same rule Axios, Terraform and Spring Boot use.
test "wins decides which side is authoritative" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = stale(hs)
  let checking = @jwt.Policy::new(expiry=true)
  // Default: the argument wins, so the expiry check is off and it passes.
  @jwt.verify(token[:], HS256, hs, now=At(9999L), policy=checking, expiry=false)
  |> ignore
  // wins=Base: the record wins, so the check stays on and it is refused.
  try
    @jwt.verify(
      token[:],
      HS256,
      hs,
      now=At(9999L),
      policy=checking,
      expiry=false,
      wins=Base,
    )
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Expired(at=1000.0))
  } noraise {
    _ => fail("wins=Base let the argument override the policy")
  }
}

///|
/// `clash=Handle` receives the base and the merged result and its answer is
/// final, which is how a caller audits or arbitrates in a way we did not think
/// of.
test "clash hands the arbitration over" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = stale(hs)
  let checking = @jwt.Policy::new(expiry=true)
  let seen : Array[@jwt.Policy] = []
  try
    @jwt.verify(
      token[:],
      HS256,
      hs,
      now=At(9999L),
      policy=checking,
      expiry=false,
      clash=Handle(fn(base, merged) {
        seen.push(base)
        seen.push(merged)
        base
      }),
    )
    |> ignore
  catch {
    e => assert_eq(e, @jwt.Expired(at=1000.0))
  } noraise {
    _ => fail("the callback returned the base, which still checks expiry")
  }
  // It saw both, and they differ in exactly the field that was overridden.
  assert_eq(seen.length(), 2)
  assert_true(seen[0].expiry)
  assert_false(seen[1].expiry)
}

///|
/// With nothing layered over it, there is no clash and `Panic` does not fire.
test "clash only fires when there is one" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = @jwt.sign(claims(), HS256, hs)
  @jwt.verify(
    token[:],
    HS256,
    hs,
    now=Ignored,
    policy=@jwt.Policy::new(leeway=60L),
    clash=Panic,
  )
  |> ignore
}

///|
test "panic clash=Panic refuses to be given two answers" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let token = @jwt.sign(claims(), HS256, hs)
  @jwt.verify(
    token[:],
    HS256,
    hs,
    now=Ignored,
    policy=@jwt.Policy::new(leeway=1L),
    leeway=2L,
    clash=Panic,
  )
  |> ignore
}

///|
/// The header describes the signature. `extra` may add to it and may not
/// quietly rewrite it.
test "panic extra cannot rewrite the algorithm the header declares" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let forged : Map[String, Json] = Map([])
  forged["alg"] = Json::string("none")
  @jwt.sign(claims(), HS256, hs, extra=forged) |> ignore
}

///|
/// What `extra` is actually for, and the way out for someone who means it.
test "extra adds to the header, and can be forced to replace" {
  let hs = @jwt.mac(fn() { @hmac.Hmac::new(raw(secret)[:], sha(256)) })
  let named : Map[String, Json] = Map([])
  named["kid"] = Json::string("2026-09")
  let token = @jwt.sign(claims(), HS256, hs, extra=named)
  assert_eq(@jwt.header(token[:]).get("kid"), Some(Json::string("2026-09")))
  assert_eq(@jwt.header(token[:]).get("alg"), Some(Json::string("HS256")))
  // Keeping ours without complaining.
  let forged : Map[String, Json] = Map([])
  forged["alg"] = Json::string("none")
  let kept = @jwt.sign(claims(), HS256, hs, extra=forged, clash=Ignore)
  assert_eq(@jwt.header(kept[:]).get("alg"), Some(Json::string("HS256")))
  // And letting the caller have what they asked for, in writing.
  let forced = @jwt.sign(
    claims(),
    HS256,
    hs,
    extra=forged,
    wins=Extra,
    clash=Ignore,
  )
  assert_eq(@jwt.header(forced[:]).get("alg"), Some(Json::string("none")))
}
