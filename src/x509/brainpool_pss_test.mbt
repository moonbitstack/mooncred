// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Brainpool and RSASSA-PSS keys, written by OpenSSL 3.2: the brainpool curves of RFC 5639 in
// both readers, and an RSASSA-PSS key with and without the parameters that hold it to a digest.
// The PSS signature below is OpenSSL's, so the scheme read off the key is checked against an
// implementation we did not write.

///|
let brainpoolp256r1_public : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABG5uv9BaM0WaR2Kqwfb3qWY91mqm
  #|lwKuBMic0o8g9JdzcjqdDiYte7ETM8OGUSSjZsgv24pAL7Q5z80TX3Yp5ls=
  #|-----END PUBLIC KEY-----

///|
let brainpoolp256r1_private : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIGmRdawto1239GgS
  #|NPMAInGXNUPZGiJ/eyFv0oAWI/3uoUQDQgAEbm6/0FozRZpHYqrB9vepZj3WaqaX
  #|Aq4EyJzSjyD0l3NyOp0OJi17sRMzw4ZRJKNmyC/bikAvtDnPzRNfdinmWw==
  #|-----END PRIVATE KEY-----

///|
let brainpoolp384r1_public : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MHowFAYHKoZIzj0CAQYJKyQDAwIIAQELA2IABBzG+JuvwrbJ1HwPmbtQZ38mvEUo
  #|nA3sv8Wunr0EE75EID+fST8AWC30uvHyxrdf3gaiANlJmsNMERskouIbuQ4MBqoR
  #|iK0a8SrJN9Jz5A2WwDaIshU1Oj4uwwUz4JTwRA==
  #|-----END PUBLIC KEY-----

///|
let brainpoolp384r1_private : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIG6AgEAMBQGByqGSM49AgEGCSskAwMCCAEBCwSBnjCBmwIBAQQwE4DcwjdjIjqw
  #|v0HtVVvqxOQZCJT83ZxmFQLcmbfBJAaAnJ3LSsUeYuEEA9/c3cbkoWQDYgAEHMb4
  #|m6/CtsnUfA+Zu1Bnfya8RSicDey/xa6evQQTvkQgP59JPwBYLfS68fLGt1/eBqIA
  #|2Umaw0wRGySi4hu5DgwGqhGIrRrxKsk30nPkDZbANoiyFTU6Pi7DBTPglPBE
  #|-----END PRIVATE KEY-----

///|
let brainpoolp512r1_public : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEfWXnW3Cy81W0uV4h74UlkzD8
  #|sGMQlnKf+2kPkRUTCm+WFaygfsKgr/Z0nDkvB0XVJ5vEvcAbR0DVrgduch6iKSF2
  #|zanrTgL9HGtMbt5MqJuJ1a4NWuPHsV/kreu3LFhm23V5g6s+dIVf2gzTvxG34BCn
  #|8FNGJxmYEJa6/oKB1vQ=
  #|-----END PUBLIC KEY-----

///|
let brainpoolp512r1_private : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIHsAgEAMBQGByqGSM49AgEGCSskAwMCCAEBDQSB0DCBzQIBAQRAOIKIry2aOAkm
  #|9YIh7e3XZeqEPVIosaaeoKalqfOXwgIX7Mi/52sLYbjbHG5rtYk/D/oGOIYLOU85
  #|Co5RNuYYlaGBhQOBggAEfWXnW3Cy81W0uV4h74UlkzD8sGMQlnKf+2kPkRUTCm+W
  #|FaygfsKgr/Z0nDkvB0XVJ5vEvcAbR0DVrgduch6iKSF2zanrTgL9HGtMbt5MqJuJ
  #|1a4NWuPHsV/kreu3LFhm23V5g6s+dIVf2gzTvxG34BCn8FNGJxmYEJa6/oKB1vQ=
  #|-----END PRIVATE KEY-----

///|
let pss_public : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MIIBIDALBgkqhkiG9w0BAQoDggEPADCCAQoCggEBAOeMM2AD8cd0Fb5hLU5IVT/x
  #|Q+e6/jAS+znwLny5IL/dn/T29OIYi5jKWipBncYedxVMyYidc6TmFrGJFizwvrhu
  #|5iBagm5yvmJuD/KB/8kCDn0ynwJp5L25BlHiRwbOLN1SYNfPUj/FHZmxiN/IFyUm
  #|VhQiYFyZ/hBRoMLExVN5jzq3L20dwhoKr2TiIeK+/yTYqETywIfLey2Coj+T+2t8
  #|3cY+jms6w5jAB/6+TJ0iDl0OqISEUKpTcQBNhYeYPjlSI/I6JNsUsnVYx7npXg+y
  #|Dbvfp9Xn73nid/z69tQln6LJUukKgwsi+k5lItu00xTb2kY/SqNJKNlrjNPuvhsC
  #|AwEAAQ==
  #|-----END PUBLIC KEY-----

///|
let pss_private : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIIEuwIBADALBgkqhkiG9w0BAQoEggSnMIIEowIBAAKCAQEA54wzYAPxx3QVvmEt
  #|TkhVP/FD57r+MBL7OfAufLkgv92f9Pb04hiLmMpaKkGdxh53FUzJiJ1zpOYWsYkW
  #|LPC+uG7mIFqCbnK+Ym4P8oH/yQIOfTKfAmnkvbkGUeJHBs4s3VJg189SP8UdmbGI
  #|38gXJSZWFCJgXJn+EFGgwsTFU3mPOrcvbR3CGgqvZOIh4r7/JNioRPLAh8t7LYKi
  #|P5P7a3zdxj6OazrDmMAH/r5MnSIOXQ6ohIRQqlNxAE2Fh5g+OVIj8jok2xSydVjH
  #|ueleD7INu9+n1efveeJ3/Pr21CWfoslS6QqDCyL6TmUi27TTFNvaRj9Ko0ko2WuM
  #|0+6+GwIDAQABAoIBAGAmrZzU9n1DPNZCR0yHJ/N2DiM32N8AutdL4BoFzE4wS4Cv
  #|XnBXDf0EJl3+wnQnaX7sVJIJBCE5NLpDeXRvAlvXHXPY8enIdzurha7IAf4n/vlJ
  #|YJNhgs2v/Cpbou/2BNZhI3rqijaV9Z1BhlubHNVd7ofM4KQDhGelZfMLP//RpAzJ
  #|SDjp9iTQsI29J8S7oqpzt9Gz6lgddSnpk1zPBnXUFylEuqbZZIvqRAlGehRY1low
  #|ISWicZamRD+ACCgC3JoRKLQwL4FCZDsc+eaT2w/NqMh/5AIUiBZZQwmNCbNar4CJ
  #|VN8tDK/nzVKlvbpmL6TNs5c/n5l/PrCFkrHZP60CgYEA9ZrTM7ed5+VnU6/FCzkw
  #|N3uCB4OALDw3pN62RDz9EYH1YWEi/i1YWI1jFRh8F2KSE5Af271f91FtsRn+2Jrw
  #|UjU2f8PqrPM9AxX7Zbx1W6WYaHyKkfgdyjNwVbxmC15QrLBJhGrohHvDETxg7omZ
  #|3BfixC4mnXPDP3GAVhZA4GUCgYEA8VkQY0GzWpFJaYDOMHiGpN/e02NjJHGoap7c
  #|ko13lP6BfTz5jKSWQK7SPMLH6+oJZm/gb/a2CLFiJ6O0dH4xOzBJ/ZRSrdD09X2K
  #|KKVgFt4xBnDuuc2CyNAKL4IVvPa2/DOQBlOO/xK51QU2lo3ZMUDxY0u5K9PcSGNZ
  #|b3Ws/H8CgYAbGE+Afxs+gAJcKyHz0QVOuaNorMsxFhuVZrR45rmMeufVLGAt5la+
  #|vipWI3NdKRSwb8/z7/psUGFnjlSdFMq6ZwByK+zx04vBkWVAnf/ccnJT5Jls7RBs
  #|RCx6aORhELCZvID/yMOKChVFC4IuDqQYsdHkjqrX5/N8RktANAhIOQKBgQC7NL2c
  #|cDMB1l5eYtYNDQBL1YcO6zHU7ACaK32mg+s0/DFPBsP/Tw9pPvG+xcuzd8cw2Sj7
  #|UCAlIAql+rqX/eaMJcnO04VKZCIOZgGLw7OEKXdXqrPSFdITmCO+dCYOfES13f0i
  #|mx/5RPo2fSO5pm/JX7mdrvgEQgLFd6LA7UNwWwKBgHTkkomIlX8FHsfzCTVzSgoo
  #|vxktWZt6x+ere6XDyjPxQVXjpYI9cgTsVfLJ+xclwJ51Nbj7a0f9oa7UTtvSKfNN
  #|pAamZyqRH4w5J96RekM7Oi8Vqfg+aV2E8jP+UuEZpDrbZOkES6VROdsKvS5ms1fc
  #|lE2pdJpAzVornshPhqMz
  #|-----END PRIVATE KEY-----

///|
let pss256_public : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MIIBVjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcN
  #|AQEIMA0GCWCGSAFlAwQCAQUAogMCASADggEPADCCAQoCggEBALpG8rF1Ho8Iao3Z
  #|vcyIvs9rlBXKAlqIxheuN0XO4XsEU3WpM7YzMdU6r9iPQ9QUbRVfCersXF3XOOkk
  #|8bIrzbFB6XiD3xoBdghex4vYJeLOq8fPIPp5L6E+X/uroS9z9chuYh8qJJpGIo2a
  #|BXXgNlCKrb1Sp1BIPPpOn1oGyadIXSaVJd4+xZUdkzzxy+yk07N+S2oIseanzlTW
  #|disVDJ2bcGFaz0JEqgtlYo7V+yVEABTp6TnbhoE/6GmxwFjO1jY5ijC4EU3EFNpK
  #|dWH+/O7viQtZRxi+6jTDFR7htCdMcZZXo9B0tHeGK64kX1nmVhgP1wdzDv+dYKH5
  #|g7B1H7sCAwEAAQ==
  #|-----END PUBLIC KEY-----

///|
let pss256_private : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIIE8AIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZI
  #|hvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAEggSmMIIEogIBAAKCAQEAukbysXUe
  #|jwhqjdm9zIi+z2uUFcoCWojGF643Rc7hewRTdakztjMx1Tqv2I9D1BRtFV8J6uxc
  #|Xdc46STxsivNsUHpeIPfGgF2CF7Hi9gl4s6rx88g+nkvoT5f+6uhL3P1yG5iHyok
  #|mkYijZoFdeA2UIqtvVKnUEg8+k6fWgbJp0hdJpUl3j7FlR2TPPHL7KTTs35Lagix
  #|5qfOVNZ2KxUMnZtwYVrPQkSqC2VijtX7JUQAFOnpOduGgT/oabHAWM7WNjmKMLgR
  #|TcQU2kp1Yf787u+JC1lHGL7qNMMVHuG0J0xxllej0HS0d4YrriRfWeZWGA/XB3MO
  #|/51gofmDsHUfuwIDAQABAoIBAB3oh04D0oC/prAY3lcJO629BZ1L/n2/ySKDN9+u
  #|/FgOlUHmhWWDKcSlNBeuxQK3tt4AEO0VvyzYAgy5AE+NpeyIey586eTYiDWG1j43
  #|WbnlWgJuWMqui321sJ6Na4dddICWbI25bAATM7gNm0PWWJIs+gFUVIXY22WLGx3O
  #|yjDf8DZMdh6qm8pirvDTKgCCNyeTHZWK8kT+OJDi2ELwlBawV+aFdLhEEC2AdaAO
  #|ekRA4lJczT1hL/KYO0yq28Ngzao1c/teNJDD7Jfa/XvXy46gTDFas65izIhX0ixu
  #|G86qzz5DBaYJg5H32M9nSLOl2BVZ7BGZFdtjZZfXCr6CTt0CgYEA+3D/IROdzU/N
  #|V/H2i6jnvfEaPSHQ/3FB1QH4XXctGr4S69lPMG2nf42p0ezpbE+nDSug9Ibpnu2I
  #|9u3Z6Qo0vwdeGgqOPMYe9cVWgOk3cuTA11SAjGpl5xbb7N6S69bxnd8yc3TptZT0
  #|sa1fnYJ9oXZWQP9yOBP7yTzJtZwSNW8CgYEAvaeB7/BIxEe8GQBQUiqaBfBEt2Zo
  #|rPMX6dkUZRN/c6xPg1rSVRWgNV1SxxR8aAlYOvR/YH7e8cnLENiXyPKA6MBN3TH4
  #|cb5P5qgROfibww5oMAaZWg6Xzo0KYoySXLaFVOZTFl968ru0ep4HHIp67BjA6TYE
  #|elA8o7AOLja2jHUCgYANkvITBQ4V0WMShlt6+qlYFbYG6tZvk9ur9ilEUnS65tv6
  #|o4ak5KaQOkOas6F+WWZ5TYuo58eg7s3gFsMW05g5X9pyqXM4ULHHLtoWp4B40WSf
  #|u04dRnkt2owQ44sm9Dmi/jOpC/y58sqq9OMei7bgipTpeWDfKiUDniZ9iWlqPQKB
  #|gAGgWBroopccTl6ghA/QUbXPU6eG90rUYtYciHI9cpBZX+0ucDNOlise+8C9SjvS
  #|KLGIuzbmn57PLjCcyuBsQ/K7A2/sJ8dB7Il703n9ycgobXhL9jCxg1fAGeCyd+bX
  #|odkSiI/ejb1bIrcSd9kkzt0LcUwOrIcn/P0iW1zGF1apAoGAZcltYkW/3xV4KDBZ
  #|w4Bat3kvAomJjqPg8KL6JA9MAZEotqaC0kBDK2xNhqvqWSWdeljfKFKjf4xGgCRy
  #|i/TRikfgp2otu8srIOeZ5f6hgKRWXbzhiKDoOXy47/A/JyR/VjjjkueFPsPKWAu+
  #|AhU6omKLuPoMrN5ucCH8Ts0B6PM=
  #|-----END PRIVATE KEY-----

///|
/// OpenSSL's RSASSA-PSS signature of "hello\n" under `pss256_private`, SHA-256 and a 32-byte salt.
let pss256_signature : String = "aa434e5fbba6a939ccd23703c58147d61c49266da3a392771f196add9aebd5d109db971c41105a8dadb3933fa9f6ec49ea3fc890a9d45f2f9791a30ef8a1dadc10d78a8bf5ceedd587af4c2300cff734280b2db31eb91187759be0e3d4b3aa5cb9957dcc22cd61dd4346ab3e1206adb5ce383983acb55261719d9585c7e6dc3be213a1f25ddaa7b71de4f01ad8cbab4868f9ebe62947551f361cba3f0bc2656ac9a296012cef295886deae211dcf0b3c330d343444bfbcc28cf14cf9624996f1aefbd470411b20adf5e1e557c65259b2ad1ecb7cb2421f9181a04b408bc1e0b0c31da8e1f13aa8f78f123293749212e03edeb746790619662bbde61bdfda9de2"

///|
test "a brainpool key reads from its SPKI and from PKCS #8, on each of the three curves" {
  for
    pair in [
      (brainpoolp256r1_public, brainpoolp256r1_private),
      (brainpoolp384r1_public, brainpoolp384r1_private),
      (brainpoolp512r1_public, brainpoolp512r1_private),
    ] {
    let spki = @x509.Spki::read(@x509.pem(pair.0)[:])
    guard spki.key() is Ec(_) else { fail("a brainpool SPKI is not an EC key") }
    let private = @x509.PrivateKey::pem(pair.1)
    assert_true(spki.holds(private.public()))
    // A signature the private key makes is one the public key takes.
    guard private is Ec(signer) && spki.key() is Ec(verifier) else {
      fail("not EC")
    }
    let signature = signer.sign(b"hello"[:])
    assert_true(verifier.verify(b"hello"[:], signature[:]))
    assert_false(verifier.verify(b"hullo"[:], signature[:]))
  }
}

///|
test "an RSASSA-PSS key held to SHA-256 checks OpenSSL's signature" {
  let spki = @x509.Spki::read(@x509.pem(pss256_public)[:])
  assert_eq(spki.alg, "1.2.840.113549.1.1.10")
  assert_eq(spki.params, Some("2.16.840.1.101.3.4.2.1"))
  guard spki.key() is Rsa(key) else {
    fail("an RSASSA-PSS SPKI is not an RSA key")
  }
  let signature = @base16.decode(pss256_signature)
  assert_true(key.verify(b"hello\n"[:], signature[:]))
  assert_false(key.verify(b"hullo\n"[:], signature[:]))
}

///|
test "an RSASSA-PSS private key signs under the scheme it is held to" {
  let private = @x509.PrivateKey::pem(pss256_private)
  let spki = @x509.Spki::read(@x509.pem(pss256_public)[:])
  assert_true(spki.holds(private.public()))
  guard private is Rsa(signer) && spki.key() is Rsa(verifier) else {
    fail("not RSA")
  }
  let signature = signer.sign(b"moon"[:])
  assert_true(verifier.verify(b"moon"[:], signature[:]))
}

///|
test "an RSASSA-PSS key with no parameters is held to none and reads as SHA-256" {
  let spki = @x509.Spki::read(@x509.pem(pss_public)[:])
  assert_eq(spki.params, None)
  guard spki.key() is Rsa(_) else { fail("not RSA") }
  let private = @x509.PrivateKey::pem(pss_private)
  assert_true(spki.holds(private.public()))
}
