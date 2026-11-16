// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Static Diffie-Hellman keys (RFC 3279 §2.3.3, PKCS #3), from OpenSSL 3.2: an X9.42 key in RFC
// 5114's 2048-bit group, a certificate carrying it under an ECDSA root, and a PKCS #3 key in
// RFC 7919's ffdhe2048.

///|
let dh_issuer : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIBTzCB9aADAgECAhQyWFoCNspvIPvGyHHWvyx3ckxrxzAKBggqhkjOPQQDAjAV
  #|MRMwEQYDVQQDDApuYW1lZCByb290MB4XDTIwMDEwMTAwMDAwMFoXDTQwMDEwMTAw
  #|MDAwMFowFTETMBEGA1UEAwwKbmFtZWQgcm9vdDBZMBMGByqGSM49AgEGCCqGSM49
  #|AwEHA0IABJPmNSLwHABCal1lM+ypg37HjK+ISBoA55un241JpiWhpzW6PBlmeVIq
  #|7lJWKepUZ5VKrch2OAuvPndmdGhdpDqjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYD
  #|VR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQDdBQECtNAqr42M6jhY+QNw
  #|eIAY1Rr2jE2jiLNBYpZwFgIhAInvByWTACSKuQkPG7oYedPvdyfXQfE0bkrcT2Db
  #|SdkF
  #|-----END CERTIFICATE-----

///|
let dh_cert : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIEhTCCBCugAwIBAgIBCzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApuYW1lZCBy
  #|b290MB4XDTI2MTExNjAxNDg1NVoXDTQ2MDExNTAxNDg1NVowDTELMAkGA1UEAwwC
  #|ZGgwggNGMIICOQYHKoZIzj4CATCCAiwCggEBAIeo5h20tmY8/7vRnGUZWZmM7vYI
  #|Zg3Q8l0s7tRDXjsA4A348dYZV9T6999FYbKqMBbD2RE0CW+qO/QpbYMOmnwgngxk
  #|l1F6vVqKnTBrz2ftkfnmcltHWMAi4LHvQnW/e2xb/BHUX5CIuUH1TrHlm7i8OaC/
  #|EjB/XE/bcMWBsj92tjrK4cqmt5AtUlJnNUiKDvE8bZpRv6SrOtg0d5ZSTY72oWe1
  #|pBgl2WfhROUUBWQlHMrLg+a0hvazyj95cVBgJsC4V/aJlihW3tQBCr0L5iHDo5YK
  #|VOcQw3XyY3XXAUEDpLVDMMGYrxJhFtInbhFxX2k4d/rX7wnK2wlK6R4aFZcCggEA
  #|P7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VV
  #|vjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRL
  #|d33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5V
  #|pL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkV
  #|szU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRR
  #|XiMnz++YxYJmS0wPbMQWWQIhAIz4NkKnCaCXtEeZdkASnaKZsaR9HrN1C6MIsP5k
  #|9fvTA4IBBQACggEAamo5P/f818GNJ7H50HWaXvZFNvfLG5roQjcwi5aD1o9bTy/0
  #|137JEy4A58nZHPcxg0DKv3FlhpKYQVMVsNNhx0CGyJZI+5bxWEKVZqGbBdqgUrFK
  #|Czxtq+UhaBFneZZRKiJ4lpFH+YEg1+YISlaZ97VdMmm45XysAGNYPorErYCY/15E
  #|OqKxMGr/fGQDmbzmEBOkEgcfruXTlE7Kf5HSktGgcS6pzn2a4jN3EdwaG66dzNa6
  #|LbJaxdkApILLQAUZfVa4H9uLBKNe2xe4fIbafDMFO0bK8gcpWd0qnpqUk10X43O6
  #|BYIPjQ9fPat920y3QZQF0ZZq5qhC21Yj4X02q6OBhDCBgTAUBgNVHREEDTALgglh
  #|LmV4YW1wbGUwDgYDVR0PAQH/BAQDAgMIMB0GA1UdDgQWBBSh4tqzu+VXn/97K0/O
  #|TaY5VJEACDA6BgNVHSMEMzAxoRmkFzAVMRMwEQYDVQQDDApuYW1lZCByb290ghQy
  #|WFoCNspvIPvGyHHWvyx3ckxrxzAKBggqhkjOPQQDAgNIADBFAiADTsxot3Lh4HtU
  #|NYjeB8niD8vj4fssu0Xb8KQ//XqrBAIhAMAOUy3IYHaZBg5PIDjx8Q3idO70yKiH
  #|5kG1pbXGWVcx
  #|-----END CERTIFICATE-----

///|
let dh_x942 : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIICYQIBADCCAjkGByqGSM4+AgEwggIsAoIBAQCHqOYdtLZmPP+70ZxlGVmZjO72
  #|CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4M
  #|ZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmg
  #|vxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFn
  #|taQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OW
  #|ClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXAoIB
  #|AD+zLJtzE00LLndQZmDtvUhMp7GPIe8gVAf0eToaC6ElENvBUHe+Rj//T+1KrAu1
  #|Vb46bBsMa0exvDdzv36Mb2KQEij4woy7GKVa4xNBAAplAZb5Mcd6V/Ld9GPl6ewU
  #|S3d95iqquKhiisN20oLW7Thk5nmCQo68gx0UNI9vL5GTtQRa8nZxZOHfyWfB+z8u
  #|VaS9G//oO5yA0FK5hdGC6grbKjtzE9P+FMhISx4FJYi5t9K70t8BYZns0G4VV80J
  #|FbM1O7tk4Ow3f9AoNw35K1LHiRQozcZ+thhLUj0dskbDL2MHhJDwDvjWR9FI1HlU
  #|UV4jJ8/vmMWCZktMD2zEFlkCIQCM+DZCpwmgl7RHmXZAEp2imbGkfR6zdQujCLD+
  #|ZPX70wQfAh0A86UR2WuM26jOXgBd8pG5wBYP5k+THlhNi5DJBw==
  #|-----END PRIVATE KEY-----

///|
let dh_pkcs3 : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIIBPwIBADCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////rfhUWKK7Spqv
  #|3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT
  #|3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId
  #|8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu
  #|Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD
  #|/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhKFyX//////////8C
  #|AQIEHwIdAMaz0BGC1wZmsOO8AdC9n+7a2lCl/ShjLXcC0bs=
  #|-----END PRIVATE KEY-----

///|
test "dh: a certificate carrying an X9.42 key reads, and its issuer's signature holds" {
  let cert = @x509.parse(@x509.pem(dh_cert)[:])
  let issuer = @x509.parse(@x509.pem(dh_issuer)[:])
  guard cert.spki.key() is Dh(prime~, generator~, public~) else {
    fail("not a Diffie-Hellman key")
  }
  assert_eq(prime.length(), 256)
  assert_true(generator.length() > 1 && public.length() > 0)
  assert_true(cert.signed_by(issuer.spki))
}

///|
test "dh: the private keys read in either form and match what they belong to" {
  let cert = @x509.parse(@x509.pem(dh_cert)[:])
  let key = @x509.PrivateKey::pem(dh_x942)
  guard key is Dh(..) else { fail("not a Diffie-Hellman key") }
  assert_true(cert.spki.holds(key.public()))
  let ffdhe = @x509.PrivateKey::pem(dh_pkcs3)
  guard ffdhe.public() is Dh(prime~, generator~, ..) else {
    fail("not a Diffie-Hellman key")
  }
  assert_eq(prime.length(), 256)
  assert_eq(generator, b"")
  // Both write back as PKCS #3 and read again as the same key.
  for k in [key, ffdhe] {
    assert_true(@x509.PrivateKey::read(k.pkcs8()[:]).public() == k.public())
    assert_true(
      @x509.Spki::read(@x509.Spki::encode(k.public())[:]).key() == k.public(),
    )
  }
}

///|
test "dh: a Diffie-Hellman key signs nothing" {
  let key = @x509.PrivateKey::pem(dh_x942)
  let refused = try @x509.signature_value(key, b"tbs") catch {
    Unsupported(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(refused)
}
