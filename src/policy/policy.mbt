// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Certificate policies (RFC 5280 §6.1), as a module of its own so that path validation is left
// exactly as it was.
//
// §6.1 is the part of the profile that answers "may this certificate, under this authority, be
// used for this purpose", and it answers it with a tree. What is here is that tree reduced to what
// the answer depends on: for every certificate, the policies that are still valid at that depth and
// the policy each of them expects the next certificate to carry. A chain is acceptable when that
// set is not empty at the end.
//
// What is not here, and why:
//
//   * Self-issued certificates. §6.1 does not count them against the three counters. Telling one
//     from an ordinary certificate means comparing subject and authority key identifier, which
//     path building already does and which this module would have to do again; the counters are
//     therefore decremented once per certificate in the chain.
//   * Policy qualifiers. A CPS URI and a user notice are for the person reading the certificate,
//     not for the algorithm, so they are parsed past rather than kept.
//   * The `policyMappings` of a certificate that also carries `anyPolicy` in a way §6.1.4(b)
//     forbids: such a chain is refused by the "no policy survived" rule rather than named.

///|
/// Why a certificate's policies could not be read.
pub(all) suberror Refused {
  Malformed(String)
} derive(Eq, Debug)

///|
/// anyPolicy (RFC 5280 §4.2.1.4): the identifier that stands for every policy.
pub let any_policy : String = "2.5.29.32.0"

///|
/// The policy extensions of one certificate, as they bear on the tree.
pub(all) struct Cert {
  /// certificatePolicies, when the extension is there. `None` is not "no policies" — it is a
  /// certificate that does not constrain them, which §6.1.3 treats as passing the parent's set
  /// through unchanged.
  policies : Array[String]?
  /// policyMappings: what an issuer's policy is called in the subject's domain.
  mappings : Array[(String, String)]
  /// policyConstraints: how many more certificates may go by without an explicit policy.
  require_explicit : Int32?
  /// policyConstraints: how many more certificates may map a policy.
  inhibit_mapping : Int32?
  /// inhibitAnyPolicy: how many more certificates may use anyPolicy.
  inhibit_any : Int32?
} derive(Eq, Debug)

///|
/// A certificate that constrains nothing, which is what a certificate with none of these
/// extensions is.
pub fn Cert::empty() -> Cert {
  {
    policies: None,
    mappings: [],
    require_explicit: None,
    inhibit_mapping: None,
    inhibit_any: None,
  }
}

///|
/// Read the four policy extensions out of a certificate.
pub fn read(der : BytesView) -> Cert raise Refused {
  let root = only(der, "a certificate")
  let parts = items(root, "a certificate")
  if parts.length() < 1 {
    raise Malformed("a certificate without a TBS")
  }
  let mut cert = Cert::empty()
  let fields = items(parts[0], "the TBS certificate")
  for field in fields {
    // [3] EXPLICIT Extensions: a context tag around the extensions SEQUENCE.
    if field.tag != 0xA3 {
      continue
    }
    let held = items(field, "the extensions")
    if held.length() != 1 {
      raise Malformed("the extensions are not one SEQUENCE")
    }
    for extension in items(held[0], "the extensions") {
      let at = items(extension, "an extension")
      if at.length() < 2 {
        raise Malformed("an extension is an id and a value")
      }
      let oid = at[0].oid() catch { _ => raise Malformed("an extension id") }
      let value = at[at.length() - 1].octets() catch {
        _ => raise Malformed("an extension value")
      }
      match oid {
        "2.5.29.32" => cert = { ..cert, policies: Some(read_policies(value)), }
        "2.5.29.33" => cert = { ..cert, mappings: read_mappings(value), }
        "2.5.29.36" => {
          let (explicit, mapping) = read_constraints(value)
          cert = {
            ..cert,
            require_explicit: explicit,
            inhibit_mapping: mapping,
          }
        }
        "2.5.29.54" =>
          cert = {
            ..cert,
            inhibit_any: Some(read_count(value, "inhibitAnyPolicy")),
          }
        _ => ()
      }
    }
  }
  cert
}

///|
fn only(octets : BytesView, what : String) -> @asn1.Tlv raise Refused {
  let tlv = @asn1.only(octets) catch {
    _ => raise Malformed(what + " is not one DER value")
  }
  if tlv.tag != 0x30 {
    raise Malformed(what + " is not a SEQUENCE")
  }
  tlv
}

///|
fn items(tlv : @asn1.Tlv, what : String) -> Array[@asn1.Tlv] raise Refused {
  tlv.items() catch {
    _ => raise Malformed(what + " does not hold items")
  }
}

///|
/// certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation, each of which is an OID and
/// an optional list of qualifiers.
fn read_policies(value : BytesView) -> Array[String] raise Refused {
  let list = items(only(value, "certificatePolicies"), "certificatePolicies")
  let out : Array[String] = []
  for information in list {
    let parts = items(information, "a policy information")
    if parts.length() < 1 {
      raise Malformed("a policy with no identifier")
    }
    let oid = parts[0].oid() catch {
      _ => raise Malformed("a policy identifier")
    }
    if out.contains(oid) {
      raise Malformed("the policy " + oid + " appears twice")
    }
    out.push(oid)
  }
  out
}

///|
/// policyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }.
fn read_mappings(value : BytesView) -> Array[(String, String)] raise Refused {
  let list = items(only(value, "policyMappings"), "policyMappings")
  let out : Array[(String, String)] = []
  for mapping in list {
    let parts = items(mapping, "a policy mapping")
    if parts.length() != 2 {
      raise Malformed("a policy mapping is two identifiers")
    }
    let from = parts[0].oid() catch {
      _ => raise Malformed("an issuer domain policy")
    }
    let to = parts[1].oid() catch {
      _ => raise Malformed("a subject domain policy")
    }
    if out.contains((from, to)) {
      raise Malformed("the mapping of " + from + " appears twice")
    }
    out.push((from, to))
  }
  out
}

///|
/// policyConstraints ::= SEQUENCE { [0] requireExplicitPolicy, [1] inhibitPolicyMapping }, both
/// optional and both an INTEGER inside the tag.
fn read_constraints(value : BytesView) -> (Int32?, Int32?) raise Refused {
  let fields = items(only(value, "policyConstraints"), "policyConstraints")
  let mut explicit = None
  let mut mapping = None
  for field in fields {
    match field.tag {
      0x80 => explicit = Some(count_inside(field, "requireExplicitPolicy"))
      0x81 => mapping = Some(count_inside(field, "inhibitPolicyMapping"))
      _ => raise Malformed("an unexpected field in policyConstraints")
    }
  }
  (explicit, mapping)
}

///|
fn count_inside(field : @asn1.Tlv, name : String) -> Int32 raise Refused {
  let inner = @asn1.only(field.value) catch {
    _ => raise Malformed(name + " is not an INTEGER")
  }
  read_count(inner.raw, name)
}

///|
/// A SkipCerts: a non-negative INTEGER, which is what all three counters are.
fn read_count(value : BytesView, name : String) -> Int32 raise Refused {
  let tlv = @asn1.only(value) catch {
    _ => raise Malformed(name + " is not an INTEGER")
  }
  if tlv.tag != 0x02 {
    raise Malformed(name + " is not an INTEGER")
  }
  let octets = tlv.value
  if octets.length() == 0 || octets.length() > 4 {
    raise Malformed(name + " is not a count this size")
  }
  if (octets[0].to_int() & 0x80) != 0 {
    raise Malformed(name + " is negative")
  }
  let mut count = 0
  for i in 0..<octets.length() {
    count = (count << 8) | octets[i].to_int()
  }
  count
}

// ------------------------------------------------------------------------ the tree

///|
/// The policies that survive the chain, in the order they were first named.
///
/// An empty result is the answer §6.1 gives a chain that is not valid for the initial policy set.
/// `initial` is the set the relying party is willing to accept; empty means any policy, which is
/// what a caller with no opinion means.
pub fn policies(
  chain : Array[Cert],
  initial~ : Array[String],
  any~ : Bool = true,
) -> Array[String] {
  // Each entry is a policy the caller would accept, and the set the next certificate must offer
  // for it to stay alive: the same policy, or what it is mapped to.
  let start = if initial.length() == 0 { [any_policy] } else { initial }
  let mut state : Array[(String, Array[String])] = []
  for policy in start {
    push_once(state, (policy, [policy]))
  }
  let mut require_explicit : Int32? = None
  let mut inhibit_mapping : Int32? = None
  let mut inhibit_any : Int32? = None
  for cert in chain {
    // A constraint counts down, so a smaller number from this certificate binds from here on.
    require_explicit = tighter(require_explicit, cert.require_explicit)
    inhibit_mapping = tighter(inhibit_mapping, cert.inhibit_mapping)
    inhibit_any = tighter(inhibit_any, cert.inhibit_any)
    let blocked_any = any && !(inhibit_any is Some(0))
    match cert.policies {
      None =>
        // No extension is not a refusal, unless the chain has run out of patience for certificates
        // that do not say which policies they are issued under.
        if require_explicit is Some(0) {
          return []
        }
      Some(offered_all) => {
        let offered = if blocked_any {
          offered_all
        } else {
          offered_all.filter(fn(p) { p != any_policy })
        }
        let next : Array[(String, Array[String])] = []
        for entry in state {
          let (policy, expected) = entry
          // Three ways for this certificate to keep an expectation alive: the parent's anyPolicy
          // is met by anything, this certificate's anyPolicy meets anything, and otherwise the
          // two sets must share a policy.
          let wanted = if expected.contains(any_policy) {
            offered
          } else if offered.contains(any_policy) {
            expected
          } else {
            expected.filter(fn(p) { offered.contains(p) })
          }
          for candidate in wanted {
            // The policy the caller asked about is the one reported back, unless the parent had
            // no opinion — in which case this certificate is what named it.
            let reported = if expected.contains(any_policy) {
              candidate
            } else {
              policy
            }
            let ahead = if candidate == any_policy {
              [any_policy]
            } else if inhibit_mapping is Some(0) {
              [candidate]
            } else {
              mapped(cert.mappings, candidate)
            }
            push_once(next, (reported, ahead))
          }
        }
        state = next
        if state.length() == 0 {
          return []
        }
      }
    }
    require_explicit = spent(require_explicit)
    inhibit_mapping = spent(inhibit_mapping)
    inhibit_any = spent(inhibit_any)
  }
  let out : Array[String] = []
  for entry in state {
    if !out.contains(entry.0) {
      out.push(entry.0)
    }
  }
  out
}

///|
/// What a policy is called in the subject's domain, which is itself when nothing maps it.
fn mapped(pairs : Array[(String, String)], policy : String) -> Array[String] {
  let out : Array[String] = []
  for pair in pairs {
    if pair.0 == policy && !out.contains(pair.1) {
      out.push(pair.1)
    }
  }
  if out.length() == 0 {
    [policy]
  } else {
    out
  }
}

///|
fn tighter(held : Int32?, found : Int32?) -> Int32? {
  match (held, found) {
    (None, _) => found
    (_, None) => held
    (Some(a), Some(b)) => Some(if a < b { a } else { b })
  }
}

///|
fn spent(count : Int32?) -> Int32? {
  match count {
    Some(0) => Some(0)
    Some(n) => Some(n - 1)
    None => None
  }
}

///|
fn push_once(
  state : Array[(String, Array[String])],
  entry : (String, Array[String]),
) -> Unit {
  if !state.contains(entry) {
    state.push(entry)
  }
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Cert with Eq::{equal, not_equal}

///|
pub extend Cert with Debug::{to_repr}
