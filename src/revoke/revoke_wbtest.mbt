// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn bytes(hex : String) -> Bytes {
  @base16.decode(hex) catch {
    _ => panic()
  }
}

///|
fn cert(pem : String) -> @x509.Cert {
  let der = @x509.pem(pem) catch { _ => panic() }
  @x509.parse(der[:]) catch {
    _ => panic()
  }
}

///|
/// The list `openssl ca -gencrl` wrote: one withdrawn certificate, the reason it was withdrawn,
/// and a signature by the CA that issued it.
test "crl: the list reads with its entries and its reason" {
  let crl = Crl::pem(crl)
  assert_eq(crl.issuer.cn(), Some("Mooncred Test CA"))
  assert_eq(crl.entries.length(), 1)
  assert_eq(crl.entries[0].serial, cert(revoked).serial)
  assert_eq(crl.entries[0].revoked.reason, Some(1))
  assert_eq(crl.alg, "1.2.840.10045.4.3.2")
  assert_true(crl.next_update is Some(_))
}

///|
/// The signature is over the TBSCertList as it arrived, and only the issuer's key verifies it.
test "crl: the list is signed by the CA and by no one else" {
  let crl = Crl::pem(crl)
  assert_true(crl.signed_by(cert(authority).spki))
  assert_false(crl.signed_by(cert(good).spki))
}

///|
/// The three answers a list can give: one certificate is withdrawn, another is not, and a list
/// from another issuer does not speak for either.
test "crl: a serial is withdrawn or it is not" {
  let crl = Crl::pem(crl)
  assert_eq(
    crl.status(cert(revoked)),
    Revoked({ at: crl.entries[0].revoked.at, reason: Some(1), }),
  )
  assert_eq(crl.status(cert(good)), Good)
}

///|
/// A list that expired years ago is still a list — the entries parse — but it is not current, and
/// `fresh` is how a caller finds out before it believes a `Good`.
test "crl: an expired list is read but not fresh" {
  let expired = Crl::pem(crl_expired)
  assert_eq(expired.entries.length(), 1)
  assert_true(expired.fresh(expired.this_update))
  assert_false(expired.fresh(expired.this_update + 60L * 86400L))
}

///|
/// The responder's answer for a certificate that is still valid, and for one it never heard of.
test "ocsp: a good certificate reads as good" {
  let ocsp = Ocsp::parse(bytes(ocsp_good)[:])
  assert_eq(ocsp.status, 0)
  let basic = ocsp.basic.unwrap()
  assert_true(basic.signed_by(cert(authority).spki))
  assert_eq(
    ocsp.status(cert(good), cert(authority)) catch {
      _ => panic()
    },
    Good,
  )
  // A serial the responder's database never held is `unknown`, and the responder says so.
  let unknown = Ocsp::parse(bytes(ocsp_stray)[:])
  assert_eq(
    unknown.status(cert(stray), cert(authority)) catch {
      _ => panic()
    },
    Unknown,
  )
}

///|
/// A revoked certificate's answer carries the time and the reason, and the CertID is what ties the
/// answer to the certificate: an answer for another serial is no answer at all.
test "ocsp: a revoked certificate reads with its reason" {
  let ocsp = Ocsp::parse(bytes(ocsp_revoked)[:])
  let status = ocsp.status(cert(revoked), cert(authority)) catch {
    _ => panic()
  }
  match status {
    Revoked(info) => {
      assert_true(info.reason is Some(_))
      assert_true(info.at > 0L)
    }
    _ => fail("expected a revocation")
  }
  // The same response says nothing about a certificate it does not name.
  assert_eq(
    ocsp.status(cert(good), cert(authority)) catch {
      _ => panic()
    },
    Unknown,
  )
}

///|
/// A response about another issuer's certificates is not an answer about this one: the CertID
/// hashes the issuer's name and key, so passing the wrong issuer makes every field disagree.
test "ocsp: an answer is only an answer for the issuer it names" {
  let ocsp = Ocsp::parse(bytes(ocsp_good)[:])
  assert_eq(ocsp.status(cert(good), cert(good)) catch { _ => panic() }, Unknown)
}

///|
/// An answer that has aged past its nextUpdate is not current, even though it parses and its
/// signature is good.
test "ocsp: a response ages out" {
  let ocsp = Ocsp::parse(bytes(ocsp_expired)[:])
  let basic = ocsp.basic.unwrap()
  assert_true(basic.fresh(basic.produced_at))
  assert_false(basic.fresh(basic.produced_at + 2L * 86400L))
}
