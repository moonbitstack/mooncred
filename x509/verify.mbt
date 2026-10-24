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
  /// The key that signed the certificate at `at` is an RSA key below the policy's `bits`.
  Weak(at~ : Int32)
  /// More name-constraint comparisons than the policy allows: a CA with thousands of subtrees
  /// over a leaf with thousands of names is a quadratic amount of work.
  Comparisons(limit~ : Int32)
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
/// path, `budget` the signature checks spent finding it, `comparisons` the name-constraint
/// comparisons, and `bits` the smallest RSA modulus a signature is accepted under.
pub(all) struct Policy {
  usage : Usage
  depth : Int32
  budget : Int32
  comparisons : Int32
  bits : Int32
} derive(Eq, Debug)

///|
/// A server certificate; webpki's limits — six intermediates, a hundred signature checks, a
/// quarter of a million name-constraint comparisons; RSA keys of 2048 bits and up (CA/Browser
/// Forum Baseline Requirements §6.1.5).
pub let policy : Policy = {
  usage: Server,
  depth: 6,
  budget: 100,
  comparisons: 250_000,
  bits: 2048,
}

///|
/// A policy with any field changed from the preset.
pub fn Policy::new(
  usage~ : Usage = policy.usage,
  depth~ : Int32 = policy.depth,
  budget~ : Int32 = policy.budget,
  comparisons~ : Int32 = policy.comparisons,
  bits~ : Int32 = policy.bits,
) -> Policy {
  { usage, depth, budget, comparisons, bits, }
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
    compared: 0,
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
priv struct Search {
  certs : Array[Cert]
  roots : Roots
  now : Int64
  policy : Policy
  mut spent : Int32
  mut compared : Int32
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
  if rsa_bits(issuer) is Some(n) && n < self.policy.bits {
    self.note(Weak(at~))
    return false
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
fn rsa_bits(spki : Spki) -> Int32? {
  guard (spki.key() catch { _ => return None }) is Rsa(k) else { return None }
  let n = k.modulus()
  guard n.length() > 0 else { return Some(0) }
  let top = n[0].to_int()
  let mut lead = 0
  while lead < 8 && (top & (0x80 >> lead)) == 0 {
    lead = lead + 1
  }
  Some(n.length() * 8 - lead)
}

///|
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
fn Search::constrained(self : Search, anchor : Cert) -> Refused? raise Refused {
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
      if self.outside(c, nc) is Some(name) {
        return Some(Constraint(at~, name~))
      }
    }
  }
  None
}

///|
fn names_of(c : Cert) -> Array[GeneralName] {
  let out = c.exts.san.copy()
  if c.subject.rdns.length() > 0 {
    out.push(Dir(c.subject))
  }
  out
}

///|
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
/// Which list of subtrees a name is being held to. A wildcard name is read differently by the
/// two: under a permitted subtree it stands for itself, under an excluded one for every name it
/// could expand to (webpki's reading, after CVE-2025-61727).
priv enum Subtrees {
  Permitted
  Excluded
}

///|
/// The first of `c`'s names that falls outside `nc`, as text, or `None`. Every comparison
/// spends one from `policy.comparisons`.
fn Search::outside(
  self : Search,
  c : Cert,
  nc : Constraints,
) -> String? raise Refused {
  for name in names_of(c) {
    let kind = kind_of(name)
    let permitted = nc.permitted.filter(g => kind_of(g) == kind)
    let excluded = nc.excluded.filter(g => kind_of(g) == kind)
    let mut bad = false
    if permitted.length() > 0 {
      bad = true
      for p in permitted {
        match self.within(name, p, Permitted) {
          Some(true) => bad = false
          Some(false) => ()
          None => return Some(show_name(name))
        }
      }
    }
    for x in excluded {
      match self.within(name, x, Excluded) {
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
fn show_name(g : GeneralName) -> String {
  match g {
    Dns(s) | Email(s) | Uri(s) => s
    Ip(a) => @base16.encode(a[:])
    Dir(n) => @base16.encode(n.raw[:])
    Named(k, v) => k.to_string() + ":" + @base16.encode(v[:])
  }
}

///|
fn Search::within(
  self : Search,
  name : GeneralName,
  base : GeneralName,
  role : Subtrees,
) -> Bool? raise Refused {
  self.compared = self.compared + 1
  if self.compared > self.policy.comparisons {
    raise Comparisons(limit=self.policy.comparisons)
  }
  match (name, base) {
    (Dns(n), Dns(b)) => dns_within(n, b, role)
    (Email(n), Email(b)) => Some(email_within(n, b))
    (Uri(n), Uri(b)) =>
      match uri_host(n) {
        Some(h) if ip_literal(h) is None => Some(host_within(h, b))
        _ => None
      }
    (Ip(n), Ip(b)) => Some(ip_within(n, b))
    (Dir(n), Dir(b)) => Some(dir_within(n, b))
    _ => None
  }
}

///|
/// A DNS name under a dNSName constraint: equal, or a subdomain of it; a constraint written with
/// a leading dot admits subdomains only, the empty one every name; case is ignored. A wildcard
/// name under an excluded subtree is expanded one label, so `*.example.com` falls under an
/// exclusion of `bar.example.com`. `None` when either side is not a well-formed DNS name.
fn dns_within(name : String, base : String, role : Subtrees) -> Bool? {
  if !dns_id(name, wildcard=true, constraint=false) ||
    !dns_id(base, wildcard=false, constraint=true) {
    return None
  }
  let n = name.to_lower()
  let b = base.to_lower()
  if b.length() == 0 {
    return Some(true)
  }
  let under = if b.has_prefix(".") {
    n.has_suffix(b)
  } else {
    n == b || n.has_suffix("." + b)
  }
  if under {
    return Some(true)
  }
  if role is Excluded && n.strip_prefix("*") is Some(rest) {
    guard b.split_once(".") is Some((label, parent)) && label.length() > 0 else {
      return Some(false)
    }
    return Some("." + parent.to_owned() == rest.to_owned())
  }
  Some(false)
}

///|
/// The host of a URI under a URI constraint: the host itself, or with a leading dot any host
/// below it. Unlike a dNSName constraint, one without the dot names exactly one host.
fn host_within(host : String, base : String) -> Bool {
  let h = host.to_lower()
  let b = base.to_lower()
  if b.has_prefix(".") {
    h.has_suffix(b)
  } else {
    h == b
  }
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
fn before(s : String, sep : String) -> String {
  match s.split_once(sep) {
    Some((a, _)) => a.to_owned()
    None => s
  }
}

///|
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
pub impl Show for Refused with fn output(self, logger) {
  let text = match self {
    Malformed(at~, m) => "certificate \{at} is malformed: " + m
    Expired(at~) => "certificate \{at} has expired"
    Premature(at~) => "certificate \{at} is not yet valid"
    Issuer => "no issuer among the intermediates or the anchors"
    Authority(at~) => "certificate \{at} acts outside its authority"
    Signature(at~) => "the signature on certificate \{at} does not verify"
    Depth(limit~) => "more than \{limit} intermediates"
    Budget(limit~) => "more than \{limit} signature checks"
    Host(h) => "the certificate does not name " + h
    Purpose(at~) => "certificate \{at} does not allow the purpose asked for"
    Critical(at~, oid~) =>
      "certificate \{at} has an unknown critical extension " + oid
    Constraint(at~, name~) =>
      "certificate \{at} names " + name + " outside a name constraint"
    Algorithm(at~, oid~) =>
      "certificate \{at} is signed with an unsupported algorithm " + oid
    Weak(at~) =>
      "certificate \{at} is signed with an RSA key below the policy's bits"
    Comparisons(limit~) => "more than \{limit} name-constraint comparisons"
  }
  logger.write_string(text)
}

///|
pub extend Refused with Show::{to_string, output}

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
