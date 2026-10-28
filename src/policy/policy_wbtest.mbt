// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 5280 §6.1, as far as the policies go: which policy a chain is valid for, and which
// combinations of the four extensions make it valid for none.

///|
let engineering : String = "1.3.6.1.4.1.99999.1"

///|
let billing : String = "1.3.6.1.4.1.99999.2"

///|
fn with_policies(policies : Array[String]) -> Cert {
  { ..Cert::empty(), policies: Some(policies), }
}

///|
/// The ordinary cases: a chain that carries one policy all the way down is valid for it, one that
/// switches to a policy the caller did not ask for is not, and a chain that constrains nothing is
/// valid for whatever the caller asked for.
test "policy: a chain is valid for the policy it carries to the end" {
  let leaf = with_policies([engineering])
  let ca = with_policies([engineering])
  assert_eq(policies([ca, leaf], initial=[engineering]), [engineering])
  assert_eq(policies([ca, leaf], initial=[billing]), [])
  // No extension anywhere: the caller's set is not contradicted.
  assert_eq(policies([Cert::empty(), Cert::empty()], initial=[engineering]), [
    engineering,
  ])
  // No opinion from the caller: any policy, so the chain decides.
  assert_eq(policies([ca, leaf], initial=[]), [engineering])
  // The anyPolicy identifier matches whatever is on offer.
  let any = with_policies([any_policy])
  assert_eq(policies([any, leaf], initial=[engineering]), [engineering])
  assert_eq(policies([with_policies([billing]), any], initial=[billing]), [
    billing,
  ])
}

///|
/// A policy mapping renames an issuer's policy for the subject's domain: the chain stays valid for
/// the policy the caller asked about, and stops being valid for it once the mapping is inhibited.
test "policy: a mapping renames a policy without losing it" {
  let ca : Cert = {
    ..with_policies([engineering]),
    mappings: [(engineering, billing)],
  }
  let leaf = with_policies([billing])
  assert_eq(policies([ca, leaf], initial=[engineering]), [engineering])
  // The same chain with the mapping inhibited at the point it would be used: the leaf's policy is
  // no longer the one the caller asked about.
  let inhibited : Cert = { ..ca, inhibit_mapping: Some(0), }
  assert_eq(policies([inhibited, leaf], initial=[engineering]), [])
}

///|
/// requireExplicitPolicy is a countdown: while it has certificates left to spend, a certificate
/// without the extension passes the parent's policies through; once it is at zero, such a
/// certificate ends the chain.
test "policy: requiring an explicit policy ends a chain that stops saying which one" {
  let ca : Cert = { ..with_policies([engineering]), require_explicit: Some(1), }
  let leaf = with_policies([engineering])
  assert_eq(policies([ca, leaf], initial=[engineering]), [engineering])
  // One more certificate than the constraint allows to be silent.
  let silent = Cert::empty()
  assert_eq(policies([ca, silent], initial=[engineering]), [])
  // A constraint of one is spent by the first certificate, so the second must name its policy...
  assert_eq(policies([ca, silent, leaf], initial=[engineering]), [])
  // ... while a larger countdown leaves room for it.
  let patient : Cert = {
    ..with_policies([engineering]),
    require_explicit: Some(2),
  }
  assert_eq(policies([patient, silent, leaf], initial=[engineering]), [
    engineering,
  ])
}

///|
/// inhibitAnyPolicy stops the identifier that stands for every policy from being used, which is
/// what a caller wants when "any" is not good enough.
test "policy: inhibiting anyPolicy makes it stop matching" {
  let leaf = with_policies([any_policy])
  assert_eq(
    policies([with_policies([engineering]), leaf], initial=[engineering]),
    [engineering],
  )
  let strict : Cert = { ..with_policies([engineering]), inhibit_any: Some(0), }
  assert_eq(policies([strict, leaf], initial=[engineering]), [])
}

///|
/// The extensions are read out of a certificate, so the octets are the ones openssl writes: the
/// policies are an identifier each, and the counters are integers inside the constraint tags.
test "policy: the extensions are read from a certificate" {
  // A TBS with nothing in it but the extensions, which is where they are looked for.
  let policies_ext = @asn1.sequence([
    @asn1.sequence([@asn1.oid([1, 2, 3, 4])]),
    @asn1.sequence([@asn1.oid([1, 2, 3, 5])]),
  ])
  let constraints_ext = @asn1.sequence([
    @asn1.tlv(0x80, @asn1.integer(b"\x02")),
    @asn1.tlv(0x81, @asn1.integer(b"\x01")),
  ])
  let mappings_ext = @asn1.sequence([
    @asn1.sequence([@asn1.oid([1, 2, 3, 4]), @asn1.oid([1, 2, 3, 5])]),
  ])
  let any_ext = @asn1.integer(b"\x03")
  let extensions = @asn1.sequence([
    extension([2, 5, 29, 32], policies_ext),
    extension([2, 5, 29, 33], mappings_ext),
    extension([2, 5, 29, 36], constraints_ext),
    extension([2, 5, 29, 54], any_ext),
  ])
  let tbs = @asn1.sequence([@asn1.tlv(0xA3, extensions)])
  let certificate = @asn1.sequence([tbs])
  let cert = read(certificate[:])
  assert_eq(cert.policies, Some(["1.2.3.4", "1.2.3.5"]))
  assert_eq(cert.mappings, [("1.2.3.4", "1.2.3.5")])
  assert_eq(cert.require_explicit, Some(2))
  assert_eq(cert.inhibit_mapping, Some(1))
  assert_eq(cert.inhibit_any, Some(3))
  // And the chain that certificate describes: the leaf below it must carry the mapped policy.
  assert_eq(policies([cert, with_policies(["1.2.3.5"])], initial=["1.2.3.4"]), [
    "1.2.3.4",
  ])
  assert_eq(policies([cert, with_policies(["1.2.3.6"])], initial=["1.2.3.4"]), [])
}

///|
/// An extension: an identifier, and the octets of its value.
fn extension(oid : Array[Int32], value : Bytes) -> Bytes {
  @asn1.sequence([@asn1.oid(oid), @asn1.octet_string(value)])
}

///|
/// A certificate that carries the same policy twice, or a constraint that is not an integer, is
/// malformed rather than read as the first of the two.
test "policy: a repeated policy or a bad count is refused" {
  let repeated = @asn1.sequence([
    @asn1.sequence([@asn1.oid([1, 2, 3, 4])]),
    @asn1.sequence([@asn1.oid([1, 2, 3, 4])]),
  ])
  let refused = try {
    read(
      @asn1.sequence([
        @asn1.sequence([
          @asn1.tlv(0xA3, @asn1.sequence([extension([2, 5, 29, 32], repeated)])),
        ]),
      ])[:],
    )
    |> ignore
    false
  } catch {
    Malformed(_) => true
  }
  assert_true(refused)
  // A count wider than four octets is not a number of certificates anyone has.
  let negative = @asn1.tlv(0x80, @asn1.integer(b"\x01\x02\x03\x04\x05"))
  let also_refused = try {
    read(
      @asn1.sequence([
        @asn1.sequence([
          @asn1.tlv(
            0xA3,
            @asn1.sequence([
              extension([2, 5, 29, 36], @asn1.sequence([negative])),
            ]),
          ),
        ]),
      ])[:],
    )
    |> ignore
    false
  } catch {
    Malformed(_) => true
  }
  assert_true(also_refused)
}
