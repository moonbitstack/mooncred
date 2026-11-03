// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// ML-DSA in X.509 (RFC 9881). The certificates here come from two writers this library did not
// write: OpenSSL 3.5, which signs the chain `scripts/gen_credentials.py` produces, and the
// standard's own appendix C.3, whose example certificate is pinned below.

///|
/// The self-signed ML-DSA-44 certificate of RFC 9881 appendix C.3, in the base64 body of its PEM
/// envelope: subject `CN=LAMPS WG, O=IETF`, key usages digitalSignature, keyCertSign and cRLSign,
/// and a signature by the key it carries. It is the one case here that neither this library nor
/// OpenSSL produced.
let rfc9881_example : String =
  #|MIIPlDCCBgqgAwIBAgIUFZ/+byL9XMQsUk32/V4o0N44804wCwYJYIZIAWUDBAMR
  #|MCIxDTALBgNVBAoTBElFVEYxETAPBgNVBAMTCExBTVBTIFdHMB4XDTIwMDIwMzA0
  #|MzIxMFoXDTQwMDEyOTA0MzIxMFowIjENMAsGA1UEChMESUVURjERMA8GA1UEAxMI
  #|TEFNUFMgV0cwggUyMAsGCWCGSAFlAwQDEQOCBSEA17K0clSq4NtF55MNSpjSyX2P
  #|E5fReJ2voXAksxbpvslPyZRtQvGbeadBO7qjPnFJy0LtURVpOsBB+suYit61/g4d
  #|hjEYSZW1ksOX0ilOLhT5CqQUujgmiZrEP0zMrLwm6agyuVEY1ctDPL75ZgsAE44I
  #|F/YediyidMNq1VTrIqrBFi5KsBrLoeOMTv2PgLZbMz0PcuVd/nHOnB67mInnxWEG
  #|wP1zgDoq7P6v3teqPLLO2lTRK9jNNqeM+XWUO0er0l6ICsRS5XQu0ejRqCr6huWQ
  #|x1jBWuTShA2SvKGlCQ9ASWWX/KfYuVE/GhvabpUKqpjeRnUH1KT1pPBZkhZYLDVy
  #|9i7aiQWrNYFnDEoCd3oz4Mpylf2PT/bRoKOnaD1l9fX3/GDaAj6CbF+SFEwC99G6
  #|EHWYdVPqk2f8122ZC3+pnNRa/biDbUPkWfUYffBYR5cJoB6mg1k1+nBGCZDNPcG6
  #|QBupS6sd3kGsZ6szGdysoGBI1MTu8n7hOpwX0FOPQw8tZC3CQVZg3niHfY2KvHJS
  #|OXjAQuQoX0MZhGxEEmJCl2hEwQ5Va6IVtacZ5Z0MayqW05hZBx/cws3nUkp77a5U
  #|6FsxjoVOj+Ky8+36yXGRKCcKr9HlBEw6T9r9n/MfkHhLjo5FlhRKDa9YZRHT2ZYr
  #|nqla8Ze05fxg8rHtFd46W+9fib3HnZEFHZsoFudPpUUx79wcvnTUSIV/R2vNWPIc
  #|C2U7O3ak4HamVZowJxhVXMY/dIWaq6uSXwI4YcqM0Pe62yhx9n1VMm10URNa1F9K
  #|G6aRGPuyyKMO7JOS7z+XcGbJrdXHEMxkexUU0hfZWMcBfD6Q/SDATmdLkEhuk3Cj
  #|GgAdMvRzl55JBnSefkd/oLdFCPil8jeDErg8Jb04jKCw//dHi69CtxZn7arJfEax
  #|KWQ+WG5bBVoMIRlG1PNuZ1vtWGD6BCoxXZgmFk1qkjfDWl+/SVSQpb1N8ki5XEqu
  #|d4S2BWcxZqxCRbW0sIKgnpMj5i8geMW3Z4NEbe/XNq06NwLUmwiYRJAKYYMzl7xE
  #|GbMNepegs4fBkRR0xNQbU+Mql3rLbw6nXbZbs55Z5wHnaVfe9vLURVnDGncSK1IE
  #|47XCGfFoixTtC8C4AbPm6C3NQ+nA6fQXRM2YFb0byIINi7Ej8E+s0bG2hd1aKxuN
  #|u/PtkzZw8JWhgLTxktCLELj6u9/MKyRRjjLuoKXgyQTKhEeACD87DNLQuLavZ7w1
  #|W5SUAl3HsKePqA46Lb/rUTKIUdYHgZjpSTZRrnh+wCUfkiujDp9R32Km1yeEzz3S
  #|BTkxdt+jJKUSvZSXCjbdNKUUqGeR8Os28BRbCatkZRtKAxOymWEaKhxIiRYnWYdo
  #|oxFAYLpEQ0ht9RUioc6IswmFwhb45u0XjdVnswSg1Mr7qIKig0LxepqiauWNtjAI
  #|PSw1j99WbD9dYqQoVnvJ6ozpXKoPNUdLC/qPM5olCrTfzyCDvo7vvBBV4Y/hU3Du
  #|yyYFZtg/8GshGq7EPKKbVMzQD4gVokZe8LRlFcx+QfMSTwnv/3OTCatYspoUWaAL
  #|zlA46TjJZ49y6w5O5f2q5m2fhXP8l/xCtJWfS/i2HXhDPoawM11ukZHE2L9IezkF
  #|wQjP1qwksM633LfPUfhNDtaHuV6uscUzwG8NlwI9kqcIJYN7Wbpst9TlawqHwgOG
  #|KujzFbpZJejt76Z5NpoiAnZhUfFqll+fgeznbMBwtVhp5NuXhM8FyDCzJCyDEqNC
  #|MEAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFDKa
  #|B7H6u0j1KjCfEaGJj4SOIyL/MAsGCWCGSAFlAwQDEQOCCXUAZ6iVH8MI4S9oZ2Ef
  #|3CVL9Ly1FPf18v3rcvqOGgMAYWd7hM0nVZfYMVQZWWaxQWcMsOiBE0YNl4oaejiV
  #|wRykGZV3XAnWTd60e8h8TovxyTJ/xK/Vw3hlU+F9YpsPJxQnZUgUMrXnzNC6YeUc
  #|rT3Y+Vk4wjXr7O6vixauM2bzAMU1jse+nrI6HqGj2lhoZwTwSD+Wim5LH4lnCgE0
  #|s2oY1scn3JsCexJ5R5OkjHq2bt9XrBgRORTADQoRtlplL0d3Eze/dDZm/Klby9OR
  #|Ia4HUL7FWtWoy86Y5TiuUjlH1pKZdjMPyj/JXAHRQDtJ5cuoGBL0NlDdATEJNCee
  #|zQfMqzTCyjCn091QkuFjDhQjzJ+sQ6G02w49lw8Kpm1ASuh7BLTPcuz7Z+rLpNjN
  #|jmW67rR6+hHMK474mSKIZnuO3vVKnidntjLhSYc1soxvYPCLWWnl4m3XyjlrnlzD
  #|4Soec2I2AjKNZKCO9KKa81cRzIcNJjc7sbnrLv/hKXNUTESn4s3yAyRPU7N6bVIy
  #|N9ifBvb1U07WMRPI8A7/f9zVCaLYx87ym9P7GGpMjDYrPUQpOaKQdu4ycWuPrlEA
  #|2BoHIVzbHHm9373BT1LjcxjR5SbbhNFg+42hwG284VlVzcLW/XiipaWN8jnONmxt
  #|kLMui9R/wf0TCehilMDDtRznfm37b2ci5o9MP/LrTDRpMVBudDuwIZmLgPQ/bj08
  #|n+VHd8D2WADpR/kEMpDhSwG2P44mwwE4CUKGbHS0qQLOSRwMlQVEzwxpOOrLMusw
  #|JmzoLE0KNsUR6o/3xAlUmjqCZMqYPYxtXgNfJEJDp3V1iqyZK1iES3EQ0/h8m7oZ
  #|3YqNKrEpTgVV7EmVpUjcVszjWgXcSKynVVsWQd3j0Zf83zXRLwmq8+anJ3XNGCSa
  #|IecO2sZxDbaiHhwFYRkt0BGRM2QM//IPMYeXhRa/1svmbOEHGxJG9LqTffkBs+01
  #|Bp7r3/9lRZ+5t3eukpinpJrCT0AgeV3l3ujbzyCiQbboFDaPS4+kKvi+iS2eHjiu
  #|S/WkfP1Go5jksxhkceJFNPsTmGCyXGPy2/haU9hkiMg9/wmuIKm/gxRfIBh/DoIr
  #|1HWZjTuWcBGWTu2NuXeAVO/MbMtpB0u6mWYktHQcVxA2LenU+N5LEPbbHp+AmPQC
  #|RZPqBziTyx/nuVnFD+/EAbPKzeqMKhcTW6nfkKt/Md4zmi1vhWxx7c+wDlo9cyAf
  #|vsS0p5uXKK1wzaC4mBIVdPYNlZtAjBCK8asKpH3/NyYJ8xhsBjxXLLiQifKiGOpA
  #|LLBy/LyJWmo4R4zkAtUILD4FcsIyLMIJlsqWjaNdey7bwGI75hZQkBIF8QJxFVtT
  #|n4HQBtuNe2ek7e72d+bayceJvlUAFXTu6oeX9/UuS7AhuY4giNzI1pNOgNwWXRxx
  #|REmwvPrzJatZZ7cwfsKTezSSQlv2O4q70+2X2h0VtUg/pkz3GknE07S3ggDR9Qkg
  #|bywQS/42luPIADbbAKXhHaBaX/TaD/uZVn+BOZ5sqWmxEbbHtvzlSea02J1Fk4Hq
  #|kWbpuzByCJ25SuDRr+Xyn84ZDnetumQ0lBkc2ro+rZKXw8YGMyt0aX8ZwJxL4qNB
  #|/WFFEproVsOru8G7iwXgt4QP8WRBSp2kTlQUbNTF3gxOTsslkUErTnvcRQ0GpK06
  #|DRQG8wbjgewpHyw7O8Sfi34EjAzic0gwtIp501/MWmKpRUgAow9LPreiaLq2TBIQ
  #|DXEhUb9fEhY77QKeir8cpue3sShqcz9TLa5REJGqsP/8/URk7lZjiI+YWbRLp2U2
  #|D//0NPEq8fxrzNtacZRxSdx2id/yTWumtj5swjFA4yk0tunadltDMgEYuKgR+Jw9
  #|G3/yFTDnepHK41V6x8eE/4JjUAvIJWADDWxudO7oF/wsY0AnUuWe9DkW09g8IWhk
  #|NukDTdpsl08hCLF06qH3MSHJrdUAzs2GGLMCvtrXK2L3k70PcLqMXhbPSr7d1RGW
  #|gW0BlRfR4l+2LJ952SMv3xzuxgT43aX3FFVBxXk7nFrhWJWIpJpuYXRhTqASkzoZ
  #|KzsIRyW0ZbsaIsy0tgzzyhQvdoOoJn+2sKjcCzpfY6tgRD9sfucOm1sGet/cM5YP
  #|iJYei2qKMeYcvACWiI8GNGY37OzhlikbleO4xXnfJwEOYx66NjTHZqkz1/TiCBGU
  #|a7h+l/fnut6VfkxS1yZ2r5Gsdx7DUfNkEeKyzIMnYRA3zw3047lHqH714rV5VbE3
  #|yYEQWvdtYlHMFM2z9DDta59RRATOemm7AA1fYsfodrV/QPJi5qPmvpHtCvfItbdL
  #|Fg88Zh1zV5nV+0doUTXFVR9poJRE9fASlfU5qCJ9Jx5ISfvIkGz1fmfqXhUN9fE7
  #|C0Evl7IYQLguTXFznRvsXvnliwR9Ut/g85JtXUiku4F2ThCBMHBDbov6p128kP+2
  #|7LBgShM4IG80clxon8sWh6y0RLUz1MTamEYZKCXAPZzJoWhbzdNns/QTsjNP8wlu
  #|vBRtdkb6w4Vrm6GO2BXY6pQUBPcoDuymAhfAF9TxRn860OQeMcT/NRsU9Z/8nRnz
  #|3KbAuMTYsQ6qbjuLTDwfF9B4b4YUDQR22z8wlzCNLzgwFlGSI12xhf3ejRlwjGZJ
  #|J/11Up4pEegRS/c+Li2OUvQr9Jxi8XGIdEJZY1T8oVpzDJf3C29gpARWSDAXrFn0
  #|lgZHnqFyebeC1uDW8r/wGtYmI2EC53+FlOF5AFcH+3LzObZzerqwror4UMOA+B5c
  #|QMU5vDv1LFcWLzvJHMXJfCHL5nVSukXCMawr+DbeKjrkseG0UX0gpUbQy0vHIH1K
  #|2geD2xyl3TJ8jCaKOxb/Hu+KfkvtOCsh07TA+cnTV1WHR77svUcMErzHXWOFm8+U
  #|omIXALO1EiDbpu38gERRLkC84eMhRBQjKcdmlcBFsmilt3cfIofypuhMRiIFjIke
  #|00y2GEdQVsZGA/LX1HILqD4dEFDDQI2LPvCG5qe28HTfWspzsqK94IRESzm+Vmdp
  #|IjNzkTyrPI06yMvxaHGajwUtLWCReJOG/uXhswbX7EviVYyqCR4vzDLDVXAulxo/
  #|OsHaQhMX8xYOLXontx7SNCBlu/EEBww5QklKUldgd5igr7bDxsvZ6vHy/wcNIzY3
  #|RUdidnuDkpSm1hIoLz4/SW2Tm6C2u9La5evu7xAfIy1ul8LE3/P0AAAAAAAAAAAA
  #|AAAAABcmOEM=

///|
/// Whether a key is ML-DSA at all, and at which set.
fn ml_dsa_level(key : @x509.Key) -> String? {
  match key {
    MlDsa(k) =>
      Some(
        match k.kind() {
          D44 => "44"
          D65 => "65"
          D87 => "87"
        },
      )
    _ => None
  }
}

///|
/// The DER of one of the fixtures, from its PEM envelope.
fn fixture(pem : String) -> Bytes raise @asn1.Refused {
  @x509.pem(pem)
}

///|
/// The base64 body of a PEM envelope, without the envelope around it — how the appendix prints
/// its certificate.
fn body(text : String) -> Bytes {
  @base64.decode_lossy(text)
}

///|
test "ml-dsa: the certificate the standard prints as an example verifies under its own key" {
  let cert = @x509.parse(body(rfc9881_example))
  assert_eq(cert.version, 3)
  assert_eq(cert.subject.cn(), Some("LAMPS WG"))
  assert_eq(cert.subject.get("2.5.4.10"), Some("IETF"))
  // id-ml-dsa-44, in both places it is written: the signature and the subject public key.
  assert_eq(cert.alg, "2.16.840.1.101.3.4.3.17")
  assert_eq(cert.spki.alg, "2.16.840.1.101.3.4.3.17")
  assert_eq(cert.spki.params, None)
  assert_eq(cert.spki.key.bytes.length(), 1312)
  assert_eq(cert.validity, { not_before: 1580704330L, not_after: 2211424330L, })
  assert_eq(cert.exts.key_usage.unwrap().get(5), true) // keyCertSign
  assert_eq(ml_dsa_level(cert.spki.key()), Some("44"))
  // The signature is a pure ML-DSA-44 one over the TBS: 2420 octets, and it checks out.
  assert_eq(cert.sig.bytes.length(), 2420)
  assert_eq(cert.signed_by(cert.spki), true)
}

///|
test "ml-dsa: a chain OpenSSL signs under ML-DSA-65 parses, names its host and verifies" {
  let leaf = @x509.parse(fixture(mldsa_leaf))
  let ca = @x509.parse(fixture(mldsa_ca))
  assert_eq(leaf.alg, "2.16.840.1.101.3.4.3.18")
  assert_eq(leaf.spki.alg, "2.16.840.1.101.3.4.3.18")
  assert_eq(leaf.spki.key.bytes.length(), 1952)
  assert_eq(leaf.sig.bytes.length(), 3309)
  assert_eq(ml_dsa_level(leaf.spki.key()), Some("65"))
  assert_eq(leaf.issuer, ca.subject)
  assert_eq(leaf.signed_by(ca.spki), true)
  assert_eq(leaf.matches("mldsa.example.com"), true)
  assert_eq(leaf.matches("other.example.com"), false)
  assert_eq(ca.exts.ca, true)
  assert_eq(ca.signed_by(ca.spki), true)
  // The path from the leaf to the anchor OpenSSL's certificate is, at a moment both are valid.
  let roots = @x509.Roots::new(certs=[fixture(mldsa_ca)])
  let path = @x509.verify(
    [fixture(mldsa_leaf)],
    roots,
    now=leaf.validity.not_before + 3600L,
    host="mldsa.example.com",
  )
  assert_eq(path.length(), 2)
  assert_eq(path[0].subject.cn(), Some("mldsa.example.com"))
  assert_eq(path[1].subject.cn(), Some("Mooncred ML-DSA CA"))
  // A host the leaf does not name is refused, as it would be under any other key.
  try {
    @x509.verify(
      [fixture(mldsa_leaf)],
      roots,
      now=leaf.validity.not_before + 3600L,
      host="other.example.com",
    )
    |> ignore
    fail("a leaf naming another host was accepted")
  } catch {
    @x509.Host(h) => assert_eq(h, "other.example.com")
    e => fail("expected Host, got \{e}")
  }
}

///|
test "ml-dsa: each parameter set carries its own identifier and key length" {
  let cases : Array[(String, String, Int32, Int32)] = [
    (mldsa_44, "2.16.840.1.101.3.4.3.17", 1312, 2420),
    (mldsa_ca, "2.16.840.1.101.3.4.3.18", 1952, 3309),
    (mldsa_87, "2.16.840.1.101.3.4.3.19", 2592, 4627),
  ]
  for case in cases {
    let (pem, oid, public, signature) = case
    let cert = @x509.parse(fixture(pem))
    assert_eq(cert.alg, oid)
    assert_eq(cert.spki.alg, oid)
    assert_eq(cert.spki.key.bytes.length(), public)
    assert_eq(cert.sig.bytes.length(), signature)
    assert_eq(cert.signed_by(cert.spki), true)
  }
  // A signature over one set does not verify under a key of another: the lengths differ, and the
  // algorithm the signature names is not the algorithm the key is.
  let leaf = @x509.parse(fixture(mldsa_leaf))
  let four = @x509.parse(fixture(mldsa_44))
  assert_eq(leaf.signed_by(four.spki), false)
  assert_eq(four.signed_by(leaf.spki), false)
}

///|
test "ml-dsa: a private key reads back as the key its certificate names" {
  let cert = @x509.parse(fixture(mldsa_leaf))
  let key = @x509.PrivateKey::pem(mldsa_key)
  // The same key from the seed alone, the form RFC 9881 §6 recommends for storage: a byte
  // string this library has to expand before it can sign with it.
  let seeded = @x509.PrivateKey::read(@base16.decode_lossy(mldsa_seed_only))
  assert_eq(key.public() == cert.spki.key(), true)
  assert_eq(seeded.public() == cert.spki.key(), true)
  assert_eq(ml_dsa_level(key.public()), Some("65"))
  // The pairing question, asked directly rather than through a round trip of the encoding.
  assert_eq(cert.spki.holds(key.public()), true)
  assert_eq(cert.spki.holds(@x509.parse(fixture(mldsa_44)).spki.key()), false)
  // What this package writes is the expanded key, and it reads back as itself.
  let written = @x509.PrivateKey::read(key.pkcs8())
  assert_eq(written.public() == cert.spki.key(), true)
}

///|
test "ml-dsa: a private key whose seed and expanded halves disagree is refused" {
  let tampered = @base16.decode_lossy(mldsa_seed_tampered)
  try {
    @x509.PrivateKey::read(tampered) |> ignore
    fail("a key whose halves disagree was read")
  } catch {
    @asn1.Malformed(m) =>
      assert_eq(m, "the ML-DSA seed does not expand to the key beside it")
    e => fail("expected Malformed, got \{e}")
  }
}

///|
test "ml-dsa: a certificate this library signs verifies under its own key" {
  let key = @x509.PrivateKey::pem(mldsa_key)
  let der = @x509.self_signed(
    key~,
    cn="issued.example",
    serial=b"\x07",
    not_before=1793232000L,
    not_after=1824768000L,
    exts={
      ..@x509.Exts::empty(),
      san: [Dns("issued.example")],
      key_usage: Some({ bytes: b"\x80", unused: 7, }),
    },
  )
  let cert = @x509.parse(der)
  assert_eq(cert.alg, "2.16.840.1.101.3.4.3.18")
  assert_eq(cert.spki.alg, "2.16.840.1.101.3.4.3.18")
  assert_eq(cert.sig.bytes.length(), 3309)
  assert_eq(cert.validity, { not_before: 1793232000L, not_after: 1824768000L, })
  assert_eq(cert.matches("issued.example"), true)
  assert_eq(cert.signed_by(cert.spki), true)
  // Its own subject is its issuer, so it is its own anchor: a path of one.
  let roots = @x509.Roots::new(certs=[der])
  let path = @x509.verify(
    [der],
    roots,
    now=1793232001L,
    host="issued.example",
    policy=@x509.Policy::new(usage=Any),
  )
  assert_eq(path.length(), 2)
}

///|
test "ml-dsa: a key that cannot encipher may not say it does (RFC 9881 §5)" {
  let key = @x509.PrivateKey::pem(mldsa_key)
  // What a certificate with these keyUsage bits is judged to be, as text, so one assertion can
  // say which answer came back.
  let judged = fn(bits : Bytes) -> String {
    let der = @x509.self_signed(
      key~,
      cn="usage.example",
      serial=b"\x08",
      not_before=1793232000L,
      not_after=1824768000L,
      exts={
        ..@x509.Exts::empty(),
        san: [Dns("usage.example")],
        key_usage: Some({ bytes: bits, unused: 0, }),
      },
    ) catch {
      _ => return "not issued"
    }
    let roots = @x509.Roots::new(certs=[der]) catch { _ => return "no anchor" }
    try {
      @x509.verify(
        [der],
        roots,
        now=1793232001L,
        host="usage.example",
        policy=@x509.Policy::new(usage=Any),
      )
      |> ignore
      "accepted"
    } catch {
      @x509.KeyUsage(at~) => "KeyUsage at \{at}"
      e => "refused: \{e}"
    }
  }
  // digitalSignature and keyCertSign: what a signing key may assert.
  assert_eq(judged(b"\x84"), "accepted")
  // keyEncipherment, and then keyAgreement, on a key that can do neither.
  assert_eq(judged(b"\xa0"), "KeyUsage at 0")
  assert_eq(judged(b"\x88"), "KeyUsage at 0")
}

///|
/// `octets` with one bit of the byte at `at` flipped.
fn flip(octets : Bytes, at : Int32) -> Bytes {
  let out = Buffer()
  out.write_bytes(octets[0:at])
  out.write_byte((octets[at].to_int() ^ 1).to_byte())
  out.write_bytes(octets[at + 1:])
  out.to_bytes()
}

///|
/// The check a verifier that only reads the algorithm gets wrong: a signature is over these bytes
/// and no others, and it is these octets and no others.
test "ml-dsa: another message, or another signature, does not verify" {
  let cert = @x509.parse(fixture(mldsa_leaf))
  let ca = @x509.parse(fixture(mldsa_ca))
  let ok = @x509.signature_ok(
    cert.tbs,
    alg=cert.alg,
    params=cert.params,
    sig=cert.sig,
    key=ca.spki,
  )
  assert_eq(ok, true)
  // One bit of the TBSCertificate changed: the CA signed something else.
  let other = flip(cert.tbs.to_owned(), 40)
  assert_eq(
    @x509.signature_ok(
      other,
      alg=cert.alg,
      params=cert.params,
      sig=cert.sig,
      key=ca.spki,
    ),
    false,
  )
  // One bit of the signature changed, with the message left as it was.
  let sig = cert.sig
  assert_eq(
    @x509.signature_ok(
      cert.tbs,
      alg=cert.alg,
      params=cert.params,
      sig={ bytes: flip(sig.bytes, sig.bytes.length() - 1), unused: 0, },
      key=ca.spki,
    ),
    false,
  )
}

///|
/// The identifier says how long the key is, and a key of another length wearing it is refused
/// before anything tries to use it: a 1312-octet key under the ML-DSA-65 identifier is an
/// ML-DSA-44 key with a claim it cannot support.
test "ml-dsa: a key of another length under an identifier is refused" {
  let cert = @x509.parse(fixture(mldsa_44))
  let wrong : @x509.Spki = {
    alg: "2.16.840.1.101.3.4.3.18",
    params: None,
    key: cert.spki.key,
  }
  try {
    wrong.key() |> ignore
    fail("a key of the wrong length was read")
  } catch {
    @asn1.Malformed(m) =>
      assert_eq(m, "an ML-DSA key of 1312 octets where 1952 are asked for")
    e => fail("expected Malformed, got \{e}")
  }
  // The parameters are absent for ML-DSA, and a NULL there is not the same encoding.
  let with_params : @x509.Spki = {
    alg: "2.16.840.1.101.3.4.3.17",
    params: Some("2.16.840.1.101.3.4.3.17"),
    key: cert.spki.key,
  }
  try {
    with_params.key() |> ignore
    fail("an ML-DSA key with parameters was read")
  } catch {
    @asn1.Malformed(m) => assert_eq(m, "ML-DSA key with parameters")
    e => fail("expected Malformed, got \{e}")
  }
}
