// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// CBOR Web Token (RFC 8392): the claim set, the numbers it is written with, and the two judgements
// a verifier makes about time.

///|
fn claimset() -> Claims {
  Claims::new(
    iss="moonbitstack",
    sub="device-7",
    aud="moonapi",
    exp=4102444800L,
    nbf=1600000000L,
    iat=1600000000L,
    cti=from_hex("00112233"),
  )
}

///|
/// The seven registered claims travel under their numbers, not their names: `iss` is 1, `aud` is 3,
/// `exp` is 4. Writing the numbers is what makes a CWT smaller than a JWT, and reading them back is
/// what makes it the same claim set.
test "cwt: the claim set is a map under numbers" {
  let value = claimset().value()
  assert_eq(value.get(Int(1)), Some(Text("moonbitstack")))
  assert_eq(value.get(Int(2)), Some(Text("device-7")))
  assert_eq(value.get(Int(3)), Some(Text("moonapi")))
  assert_eq(value.get(Int(4)), Some(Int(4102444800L)))
  assert_eq(value.get(Int(5)), Some(Int(1600000000L)))
  assert_eq(value.get(Int(6)), Some(Int(1600000000L)))
  assert_eq(value.get(Int(7)), Some(Bytes(from_hex("00112233"))))
  // And back: the same claims, having gone through the encoding.
  let octets = @cbor.encode(value)
  let back = @cbor.decode(octets[:]) catch { _ => panic() }
  assert_eq(Claims::of(back), claimset())
  // The empty claim set is an empty map, which is a token that says nothing rather than nothing.
  assert_eq(@cbor.encode(Claims::new().value()), from_hex("a0"))
}

///|
/// A claim set with a private claim in it keeps the registered ones and drops the rest, and a
/// registered claim of the wrong type is refused rather than read as absent.
test "cwt: unknown claims are dropped and mistyped ones are refused" {
  let octets = @cbor.encode(
    @cbor.Map([
      (Int(1), Text("issuer")),
      (Int(100), Text("private")),
      (Text("name"), Int(1)),
    ]),
  )
  let value = @cbor.decode(octets[:]) catch { _ => panic() }
  let claims = Claims::of(value)
  assert_eq(claims.iss, Some("issuer"))
  assert_eq(claims.sub, None)
  // A numeric claim that is a text string, and an audience that is a list, which this type does
  // not carry: both are messages the writer got wrong.
  let mistyped = @cbor.encode(@cbor.Map([(Int(4), Text("soon"))]))
  let refused = try {
    let read = @cbor.decode(mistyped[:]) catch { _ => panic() }
    Claims::of(read) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(refused)
  let listed = @cbor.encode(
    @cbor.Map([(Int(3), Array([Text("a"), Text("b")]))]),
  )
  let also_refused = try {
    let read = @cbor.decode(listed[:]) catch { _ => panic() }
    Claims::of(read) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(also_refused)
  // A claim that is explicitly null is absent, which is a different thing from being wrong.
  let empty = @cbor.encode(@cbor.Map([(Int(1), Null)]))
  let nulled = Claims::of(@cbor.decode(empty[:]) catch { _ => panic() })
  assert_eq(nulled.iss, None)
}

///|
/// A signed claim set, and the clock: valid at a moment inside its window, expired after `exp`,
/// and too early before `nbf`, with the leeway going either way.
test "cwt: a signed claim set is judged by the clock the caller names" {
  let key = from_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let signer : &@spec.Signer = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let verifier : &@spec.Verifier = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let message = signed(
    claimset(),
    alg=Hs256,
    signer,
    kid=Some(from_hex("abcd")),
  )
  assert_eq(
    verified(message[:], alg=Hs256, verifier, now=At(1700000000L)),
    claimset(),
  )
  // Inside the window and past it: the token expires at 4102444800, so an hour later is too late
  // and a minute later is within the leeway.
  let late = try {
    verified(message[:], alg=Hs256, verifier, now=At(4102444801L), leeway=0L)
    |> ignore
    false
  } catch {
    Expired(at~) => at == 4102444800L
    _ => false
  }
  assert_true(late)
  assert_eq(
    verified(message[:], alg=Hs256, verifier, now=At(4102444830L), leeway=60L),
    claimset(),
  )
  let early = try {
    verified(message[:], alg=Hs256, verifier, now=At(1500000000L), leeway=0L)
    |> ignore
    false
  } catch {
    TooEarly(at~) => at == 1600000000L
    _ => false
  }
  assert_true(early)
  // With no clock at all, the times are the caller's business and nothing is judged.
  assert_eq(verified(message[:], alg=Hs256, verifier), claimset())
}

///|
/// A claim set MACed rather than signed: the same claims, a different structure, and a payload an
/// anyone can read.
test "cwt: a MACed claim set carries the same claims" {
  let key = from_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let tagger : &@spec.Signer = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let verifier : &@spec.Verifier = mac(fn() { @hmac.Hmac::new(key[:], sha256) })
  let message = macd(claimset(), alg=Hs256, tagger)
  assert_eq(message[0], b'\xd1') // tag 17
  assert_eq(uncovered(message[:], alg=Hs256, verifier), claimset())
  // A COSE_Mac0 handed to the signature verifier is refused: the two structures are not
  // interchangeable even when the key and the algorithm are the same.
  let wrong = try {
    verified(message[:], alg=Hs256, verifier) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(wrong)
}
