// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Certification path validation (RFC 5280 §6) as a TLS client needs it: from the peer's leaf,
// through whatever intermediates it sent, to a trust anchor the caller holds. The choices that
// RFC 5280 leaves open follow webpki, the validator rustls uses, and Go's crypto/x509 where the
// two agree; each is named where it is made.

///|
/// Why a chain was refused. `at` is the position in the chain as given — 0 the leaf, then the
/// intermediates in the order they arrived — of the certificate the refusal is about.
pub(all) suberror Refused {
  /// The certificate at `at` does not parse; the message says where it stopped.
  Malformed(at~ : Int32, String)
  /// Past its notAfter.
  Expired(at~ : Int32)
  /// Before its notBefore.
  Premature(at~ : Int32)
  /// No issuer for the certificate the search ended on, among the intermediates or the anchors.
  Issuer
  /// A certificate acting outside its authority: an issuer that is not a CA, or has no
  /// keyCertSign, or sits deeper than its pathLenConstraint allows; or a leaf that is a CA.
  Authority(at~ : Int32)
  /// Its issuer's signature does not verify.
  Signature(at~ : Int32)
  /// More intermediates than the policy allows.
  Depth(limit~ : Int32)
  /// More signature checks than the policy allows: a peer can send a pile of cross-signed
  /// certificates sharing one name, and each candidate costs a verification.
  Budget(limit~ : Int32)
  /// The leaf does not name the host.
  Host(String)
  /// The leaf, or an issuer that restricts its key purposes, does not allow the one asked for.
  Purpose(at~ : Int32)
  /// A critical extension this validator does not understand (RFC 5280 §4.2).
  Critical(at~ : Int32, oid~ : String)
  /// A name in the certificate at `at` falls outside a name constraint above it.
  Constraint(at~ : Int32, name~ : String)
  /// A signature algorithm this validator does not check.
  Algorithm(at~ : Int32, oid~ : String)
} derive(Eq, Debug)

///|
/// The key purpose the leaf must allow (RFC 5280 §4.2.1.12). `Any` asks for none and checks
/// nothing; `Other` names a purpose by OID.
pub(all) enum Usage {
  Server
  Client
  Any
  Other(String)
} derive(Eq, Debug)

///|
/// The OID a usage asks for, `None` for `Any`.
fn Usage::oid(self : Usage) -> String? {
  match self {
    Server => Some(eku_server_auth)
    Client => Some(eku_client_auth)
    Any => None
    Other(o) => Some(o)
  }
}

///|
/// What a validation asks for and how far it may go. `depth` bounds the intermediates on the
/// path and `budget` the signature checks spent finding it; the presets are webpki's.
pub(all) struct Policy {
  usage : Usage
  depth : Int32
  budget : Int32
} derive(Eq, Debug)

///|
/// A server certificate, at most six intermediates, at most a hundred signature checks.
pub let policy : Policy = { usage: Server, depth: 6, budget: 100, }

///|
/// A policy with any field changed from the preset.
pub fn Policy::new(
  usage~ : Usage = policy.usage,
  depth~ : Int32 = policy.depth,
  budget~ : Int32 = policy.budget,
) -> Policy {
  { usage, depth, budget, }
}

///|
/// Trust anchors. An anchor is a name and a key: its own validity and signature are never
/// checked, which is what lets a long-lived root carry a SHA-1 self-signature. Its name
/// constraints, when it has them, bind everything below it.
pub struct Roots {
  priv certs : Array[Cert]
  priv by_subject : Map[Bytes, Array[Int32]]
}

///|
/// Anchors from DER certificates.
pub fn Roots::new(certs? : ArrayView[Bytes]) -> Roots raise @asn1.Refused {
  let roots : Roots = { certs: [], by_subject: Map([]), }
  if certs is Some(list) {
    for der in list {
      roots.add(der[:])
    }
  }
  roots
}

///|
/// Anchors from a PEM bundle such as `/etc/ssl/certs/ca-certificates.crt` or curl's `cacert.pem`.
pub fn Roots::pem(bundle : String) -> Roots raise @asn1.Refused {
  Roots::new(certs=pems(bundle)[:])
}

///|
/// Add one anchor. The same certificate added twice is kept once.
pub fn Roots::add(self : Roots, der : BytesView) -> Unit raise @asn1.Refused {
  let cert = parse(der.to_owned()[:])
  let key = cert.subject.raw
  let slot = self.by_subject.get(key).unwrap_or([])
  for i in slot {
    if self.certs[i].raw == cert.raw {
      return
    }
  }
  slot.push(self.certs.length())
  self.by_subject[key] = slot
  self.certs.push(cert)
}

///|
/// How many anchors there are.
pub fn Roots::length(self : Roots) -> Int32 {
  self.certs.length()
}

///|
/// The anchors, in the order they were added.
pub fn Roots::iter(self : Roots) -> Iter[Cert] {
  self.certs.iter()
}

///|
/// The anchors whose subject is `name`, byte for byte.
fn Roots::named(self : Roots, name : Bytes) -> Array[Cert] {
  match self.by_subject.get(name) {
    Some(ids) => ids.map(i => self.certs[i])
    None => []
  }
}

///|
/// Validate a chain and return the path found: the leaf, the intermediates it runs through, and
/// the anchor it ends on.
///
/// `chain` is the leaf followed by the intermediates the peer sent, in any order; ones the path
/// does not need are ignored, which is what a TLS server's habit of sending a cross-signed extra
/// asks for. `now` is the time to judge validity at, in seconds since the Unix epoch. `host`,
/// when given, is a DNS name or an IP literal the leaf must name; without it names are not
/// compared.
///
/// The rules, and whose they are:
/// - Names come from subjectAltName only, never the commonName (RFC 6125, Go since 1.15, webpki).
/// - Every issuer must be a CA, have keyCertSign when it lists key usages, and respect its
///   pathLenConstraint. A leaf that is a CA is refused, as webpki does.
/// - Validity is checked on every certificate but the anchor.
/// - The leaf must allow `policy.usage`; an issuer that lists key purposes must allow it too
///   (Go and the Mozilla root programme chain the restriction).
/// - An unknown critical extension anywhere on the path refuses it.
/// - Name constraints bind dNSName, iPAddress, rfc822Name, directoryName and the host of a URI;
///   a constraint of another form, over a name of that form, refuses rather than guesses.
/// - Several candidate issuers with the issuer's name are each tried, preferring the one whose
///   subjectKeyIdentifier matches the authorityKeyIdentifier; every signature check spends from
///   `policy.budget`.
///
/// When no path works, the refusal is the first reason a candidate path failed, or `Issuer` when
/// there was no candidate at all.
pub fn verify(
  chain : ArrayView[Bytes],
  roots : Roots,
  now~ : Int64,
  host? : String,
  policy~ : Policy = policy,
) -> Array[Cert] raise Refused {
  if chain.length() == 0 {
    raise Malformed(at=0, "empty chain")
  }
  let certs : Array[Cert] = []
  for i, der in chain {
    certs.push(
      parse(der[:]) catch {
        @asn1.Malformed(m) | @asn1.Unsupported(m) => raise Malformed(at=i, m)
      },
    )
  }
  let leaf = certs[0]
  check_common(leaf, 0, now)
  if leaf.exts.ca {
    raise Authority(at=0)
  }
  if !allows(leaf.exts.eku, policy.usage) {
    raise Purpose(at=0)
  }
  if host is Some(h) && !leaf.matches(h) {
    raise Host(h)
  }
  let search : Search = {
    certs,
    roots,
    now,
    policy,
    spent: 0,
    first: None,
    path: [(leaf, 0)],
  }
  match search.grow() {
    Some(path) => path
    None =>
      match search.first {
        Some(e) => raise e
        None => raise Issuer
      }
  }
}

///|
/// The checks every certificate on the path but the anchor takes.
fn check_common(c : Cert, at : Int32, now : Int64) -> Unit raise Refused {
  if c.exts.unknown_critical.get(0) is Some(oid) {
    raise Critical(at~, oid~)
  }
  if now < c.validity.not_before {
    raise Premature(at~)
  }
  if now > c.validity.not_after {
    raise Expired(at~)
  }
}

///|
/// Whether an extKeyUsage allows `usage`. An absent extension allows everything; for an issuer,
/// anyExtendedKeyUsage allows everything too, and for the leaf as well — RFC 5280 lets it stand
/// for any purpose, and webpki and Go both honour it.
fn allows(eku : Array[String]?, usage : Usage) -> Bool {
  match (eku, usage.oid()) {
    (None, _) | (_, None) => true
    (Some(list), Some(oid)) => list.contains(oid) || list.contains(eku_any)
  }
}

///|
/// The state of one path search.
priv struct Search {
  certs : Array[Cert]
  roots : Roots
  now : Int64
  policy : Policy
  mut spent : Int32
  mut first : Refused?
  path : Array[(Cert, Int32)]
}

///|
/// Keep the first reason a candidate failed: it is about the path the peer most likely meant.
fn Search::note(self : Search, e : Refused) -> Unit {
  if self.first is None {
    self.first = Some(e)
  }
}

///|
/// Whether `child` (at chain position `at`) is signed by `issuer`, spending one check from the
/// budget. An unsupported algorithm is noted and counts as not signed.
fn Search::signed(
  self : Search,
  child : Cert,
  at : Int32,
  issuer : Spki,
) -> Bool raise Refused {
  self.spent = self.spent + 1
  if self.spent > self.policy.budget {
    raise Budget(limit=self.policy.budget)
  }
  let ok = child.signed_by(issuer) catch {
    @asn1.Unsupported(_) => {
      self.note(Algorithm(at~, oid=child.alg))
      return false
    }
    @asn1.Malformed(m) => {
      self.note(Malformed(at~, m))
      return false
    }
  }
  if !ok {
    self.note(Signature(at~))
  }
  ok
}

///|
/// Extend the path from its last certificate to an anchor, depth first.
fn Search::grow(self : Search) -> Array[Cert]? raise Refused {
  let (child, child_at) = self.path[self.path.length() - 1]
  for anchor in self.roots.named(child.issuer.raw) {
    if self.signed(child, child_at, anchor.spki) {
      match self.constrained(anchor) {
        Some(e) => self.note(e)
        None => {
          let out = self.path.map(p => p.0)
          out.push(anchor)
          return Some(out)
        }
      }
    }
  }
  let intermediates = self.path.length() - 1
  let candidates = self.candidates(child)
  if candidates.length() > 0 && intermediates >= self.policy.depth {
    self.note(Depth(limit=self.policy.depth))
    return None
  }
  for at in candidates {
    let cand = self.certs[at]
    let ok = self.issuer_ok(cand, at, intermediates) catch {
      e => {
        self.note(e)
        false
      }
    }
    if ok && self.signed(child, child_at, cand.spki) {
      self.path.push((cand, at))
      if self.grow() is Some(p) {
        return Some(p)
      }
      self.path.pop() |> ignore
    }
  }
  None
}

///|
/// The positions of the intermediates that could have issued `child`: named by its issuer, not
/// already on the path, the one whose subjectKeyIdentifier matches `child`'s
/// authorityKeyIdentifier tried first.
fn Search::candidates(self : Search, child : Cert) -> Array[Int32] {
  let likely = []
  let rest = []
  for at in 1..<self.certs.length() {
    let c = self.certs[at]
    if c.subject.raw != child.issuer.raw {
      continue
    }
    if self.path.iter().any(p => p.0.raw == c.raw) {
      continue
    }
    if child.exts.aki is Some(k) && c.exts.ski == Some(k) {
      likely.push(at)
    } else {
      rest.push(at)
    }
  }
  likely + rest
}

///|
/// Whether `cand` may issue for a path with `below` intermediates under it.
fn Search::issuer_ok(
  self : Search,
  cand : Cert,
  at : Int32,
  below : Int32,
) -> Bool raise Refused {
  check_common(cand, at, self.now)
  if !cand.exts.ca {
    raise Authority(at~)
  }
  if cand.exts.key_usage is Some(ku) && !ku.get(5) {
    raise Authority(at~)
  }
  if cand.exts.path_len is Some(n) && below > n {
    raise Authority(at~)
  }
  if !allows(cand.exts.eku, self.policy.usage) {
    raise Purpose(at~)
  }
  true
}

///|
/// The first name constraint the finished path breaks, with `anchor` on top of it, or `None`.
fn Search::constrained(self : Search, anchor : Cert) -> Refused? {
  let path = self.path
  let tops : Array[(Cert, Int32)] = [(anchor, path.length())]
  for k in 1..<path.length() {
    tops.push((path[k].0, k))
  }
  for top in tops {
    let (ca, k) = top
    guard ca.exts.constraints is Some(nc) else { continue }
    for i in 0..<k {
      let (c, at) = path[i]
      if outside(c, nc) is Some(name) {
        return Some(Constraint(at~, name~))
      }
    }
  }
  None
}

///|
/// The names a certificate is held to under a constraint: its subjectAltName entries and, when
/// it is not empty, its subject as a directoryName.
fn names_of(c : Cert) -> Array[GeneralName] {
  let out = c.exts.san.copy()
  if c.subject.rdns.length() > 0 {
    out.push(Dir(c.subject))
  }
  out
}

///|
/// The kind a GeneralName is, as its field number.
fn kind_of(g : GeneralName) -> Int32 {
  match g {
    Email(_) => 1
    Dns(_) => 2
    Dir(_) => 4
    Uri(_) => 6
    Ip(_) => 7
    Named(n, _) => n
  }
}

///|
/// The first of `c`'s names that falls outside `nc`, as text, or `None`.
fn outside(c : Cert, nc : Constraints) -> String? {
  for name in names_of(c) {
    let kind = kind_of(name)
    let permitted = nc.permitted.filter(g => kind_of(g) == kind)
    let excluded = nc.excluded.filter(g => kind_of(g) == kind)
    let mut bad = false
    if permitted.length() > 0 {
      bad = true
      for p in permitted {
        match within(name, p) {
          Some(true) => bad = false
          Some(false) => ()
          None => return Some(show_name(name))
        }
      }
    }
    for x in excluded {
      match within(name, x) {
        Some(true) | None => bad = true
        Some(false) => ()
      }
    }
    if bad {
      return Some(show_name(name))
    }
  }
  None
}

///|
/// A GeneralName as text, for a refusal.
fn show_name(g : GeneralName) -> String {
  match g {
    Dns(s) | Email(s) | Uri(s) => s
    Ip(a) => @base16.encode(a[:])
    Dir(n) => @base16.encode(n.raw[:])
    Named(k, v) => k.to_string() + ":" + @base16.encode(v[:])
  }
}

///|
/// Whether `name` lies inside the subtree `base` (RFC 5280 §4.2.1.10), or `None` when the form
/// is one this validator cannot judge.
fn within(name : GeneralName, base : GeneralName) -> Bool? {
  match (name, base) {
    (Dns(n), Dns(b)) => Some(dns_within(n, b))
    (Email(n), Email(b)) => Some(email_within(n, b))
    (Uri(n), Uri(b)) =>
      match uri_host(n) {
        Some(h) => Some(ip_literal(h) is None && dns_within(h, b))
        None => None
      }
    (Ip(n), Ip(b)) => Some(ip_within(n, b))
    (Dir(n), Dir(b)) => Some(dir_within(n, b))
    _ => None
  }
}

///|
/// A DNS name under a dNSName constraint: equal, or a subdomain of it; a constraint written
/// with a leading dot admits subdomains only (the Go and OpenSSL reading). The empty constraint
/// admits every name. Case is ignored.
fn dns_within(name : String, base : String) -> Bool {
  let n = name.to_lower()
  let b = base.to_lower()
  if b.length() == 0 {
    return true
  }
  if b.has_prefix(".") {
    return n.has_suffix(b)
  }
  n == b || n.has_suffix("." + b)
}

///|
/// A mailbox under an rfc822Name constraint: a whole mailbox matches exactly; a host matches
/// mailboxes at that host; a host with a leading dot matches mailboxes at any host below it.
fn email_within(name : String, base : String) -> Bool {
  guard name.split_once("@") is Some((_, host)) else { return false }
  let h = host.to_owned().to_lower()
  if base.contains("@") {
    return name.to_lower() == base.to_lower()
  }
  let b = base.to_lower()
  if b.has_prefix(".") {
    h.has_suffix(b)
  } else {
    h == b
  }
}

///|
/// An address under an iPAddress constraint: same family, and equal to the constraint's address
/// in every bit its mask sets.
fn ip_within(addr : Bytes, base : Bytes) -> Bool {
  let n = addr.length()
  if base.length() != 2 * n {
    return false
  }
  for i in 0..<n {
    let mask = base[n + i]
    if (addr[i] & mask) != (base[i] & mask) {
      return false
    }
  }
  true
}

///|
/// A directoryName under a directoryName constraint: the constraint's RDNs are a prefix of the
/// name's, compared by encoding.
fn dir_within(name : Name, base : Name) -> Bool {
  let (ns, bs) = (rdn_raws(name), rdn_raws(base)) catch { _ => return false }
  if bs.length() > ns.length() {
    return false
  }
  for i, b in bs {
    if ns[i] != b {
      return false
    }
  }
  true
}

///|
/// `s` up to the first `sep`, or all of it.
fn before(s : String, sep : String) -> String {
  match s.split_once(sep) {
    Some((a, _)) => a.to_owned()
    None => s
  }
}

///|
/// The host of a URI: after `scheme://` and any userinfo, before the port, path, query or
/// fragment; `None` when there is no authority.
fn uri_host(uri : String) -> String? {
  guard uri.split_once("://") is Some((_, rest)) else { return None }
  let authority = before(before(before(rest.to_owned(), "/"), "?"), "#")
  let host = match authority.rev_find("@") {
    Some(i) => authority[i + 1:].to_owned()
    None => authority
  }
  let h = if host.has_prefix("[") {
    before(host, "]") + "]"
  } else {
    before(host, ":")
  }
  if h.length() == 0 {
    None
  } else {
    Some(h)
  }
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Usage with Eq::{equal, not_equal}

///|
pub extend Usage with Debug::{to_repr}

///|
pub extend Policy with Eq::{equal, not_equal}

///|
pub extend Policy with Debug::{to_repr}
