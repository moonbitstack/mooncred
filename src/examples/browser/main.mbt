// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// What docs/try.html asks for: a credential in, one JSON report out. Nothing here re-decides
// anything — the parse, the signature checks, the path building, the key usages and the wording of
// every refusal come from the packages themselves, and this file only puts them in a shape a page
// can draw.
//
// The instant is a `Double` because it arrives from JavaScript, which has one number type; an
// `Int64` parameter reads as a plain number there and stops at the first comparison. Seconds since
// the epoch up to the year 9999 are well inside what a double holds exactly.

///|
/// Read a PEM chain as the library reads it: the leaf first, then whatever intermediates were
/// pasted after it. One certificate is a chain with no intermediates.
pub fn certificate(
  input : String,
  host : String,
  at : Double,
  pasted : Bool,
) -> String {
  let now = at.to_int64()
  let ders = @x509.pems(input) catch { _ => [] }
  if ders.length() == 0 {
    return empty_report("certificate", "no PEM certificate in the text")
  }
  let certs : Array[Json] = []
  for der in ders {
    let cert = @x509.parse(der[:]) catch {
      @asn1.Malformed(m) | @asn1.Unsupported(m) =>
        return refusal_report(
          "certificate",
          "a certificate did not parse: " + m,
          "Malformed",
          None,
          certs,
          [],
        )
    }
    certs.push(summary(cert))
  }
  let wanted : String? = if host.length() == 0 { None } else { Some(host) }
  // Two trust stores, and the difference is the point: the roots a browser trusts, or the
  // certificates that were just pasted, which is how a chain under a test authority is read.
  let roots = if pasted {
    @x509.Roots::new(certs=ders[:]) catch {
      _ =>
        return empty_report(
          "certificate", "the certificates pasted are not anchors",
        )
    }
  } else {
    @roots.mozilla()
  }
  let verdict = try @x509.verify(ders[:], roots, now~, host?=wanted) catch {
    e => {
      let (code, at) = refusal(e)
      Json::object({
        "ok": Json::boolean(false),
        "line": Json::string(e.to_string()),
        "path": Json::array([]),
        "reason": at_reason(code, at, e.to_string()),
      })
    }
  } noraise {
    path => {
      let names : Array[Json] = []
      for cert in path {
        names.push(Json::string(label(cert.subject)))
      }
      // A self-signed certificate that was also pasted as an anchor ends the path it begins, and
      // saying so is clearer than printing its name twice.
      let looped = path.length() == 2 && path[0].raw == path[1].raw
      Json::object({
        "ok": Json::boolean(true),
        "line": Json::string(
          if looped {
            label(path[0].subject) +
            " is its own anchor: a self-signed certificate, trusted because it was pasted"
          } else {
            "a path of \{path.length()}: " +
            join(path.map(cert => label(cert.subject)))
          },
        ),
        "path": Json::array(names),
        "reason": Json::null(),
      })
    }
  }
  @json.dumps(
    Json::object({
      "kind": Json::string("certificate"),
      "certs": Json::array(certs),
      "verdict": verdict,
    }),
  )
}

///|
/// Read a token. A shared secret checks an HMAC token end to end; without one the claims are shown
/// as they arrived and named as unchecked, which is what they are.
pub fn token(input : String, secret : String, at : Double) -> String {
  let now = at.to_int64()
  let header = @jwt.header(input) catch {
    _ => return empty_report("token", "not a compact JWT")
  }
  let head : Array[Json] = []
  for pair in header {
    head.push(entry(pair.0, pair.1))
  }
  let alg = match header.get("alg") {
    Some(String(name)) =>
      @jwt.Alg::of(name) catch {
        _ =>
          return refusal_report(
            "token",
            "unknown alg " + name,
            "Algorithm",
            None,
            head,
            [],
          )
      }
    _ =>
      return refusal_report(
        "token",
        "the header names no algorithm",
        "Shape",
        None,
        head,
        [],
      )
  }
  let body : Array[Json] = []
  if secret.length() == 0 {
    let claims = @jwt.claims_unverified(input[:]) catch {
      _ =>
        return refusal_report(
          "token",
          "the payload is not JSON",
          "Shape",
          None,
          head,
          body,
        )
    }
    for pair in claims {
      body.push(entry(pair.0, pair.1))
    }
    return @json.dumps(
      Json::object({
        "kind": Json::string("token"),
        "header": Json::array(head),
        "claims": Json::array(body),
        "verdict": Json::object({
          "ok": Json::boolean(false),
          "line": Json::string(
            "read, not checked: with no secret given the signature and the times are unverified",
          ),
          "path": Json::array([]),
          "reason": Json::null(),
        }),
      }),
    )
  }
  let key = @jwt.mac(fn() {
    @hmac.Hmac::new(@utf8.encode(secret)[:], hasher(alg))
  })
  let verdict = try @jwt.verify(input[:], alg, key, now=At(now)) catch {
    @jwt.Refused::Signature =>
      refusal_verdict(
        "the signature does not verify under this secret",
        "Signature",
        None,
      )
    @jwt.Refused::Expired(at~) =>
      refusal_verdict(
        "the token expired at \{at.to_int()}",
        "Expired",
        Some(at.to_int64()),
      )
    @jwt.Refused::TooEarly(at~) =>
      refusal_verdict(
        "the token is valid only from \{at.to_int()}",
        "TooEarly",
        Some(at.to_int64()),
      )
    e => refusal_verdict(line_of(e), "Refused", None)
  } noraise {
    claims => {
      for pair in claims {
        body.push(entry(pair.0, pair.1))
      }
      Json::object({
        "ok": Json::boolean(true),
        "line": Json::string(
          "the signature verifies under this secret, and the times are inside the token's own",
        ),
        "path": Json::array([]),
        "reason": Json::null(),
      })
    }
  }
  @json.dumps(
    Json::object({
      "kind": Json::string("token"),
      "header": Json::array(head),
      "claims": Json::array(body),
      "verdict": verdict,
    }),
  )
}

///|
/// The digest an HMAC algorithm uses: `jwt.mac` takes a factory rather than an algorithm, so the
/// header's own name decides which one is built.
fn hasher(alg : @jwt.Alg) -> () -> &@spec.Hash {
  match alg {
    HS384 => fn() { @sha2.Hasher::new(kind=Sha384) }
    HS512 => fn() { @sha2.Hasher::new(kind=Sha512) }
    _ => fn() { @sha2.Hasher::new() }
  }
}

///|
/// One certificate as the page shows it.
fn summary(cert : @x509.Cert) -> Json {
  let names : Array[Json] = []
  for name in cert.exts.san {
    names.push(Json::string(show_name(name)))
  }
  Json::object({
    "subject": Json::string(label(cert.subject)),
    "issuer": Json::string(label(cert.issuer)),
    "from": Json::number(cert.validity.not_before.to_double()),
    "to": Json::number(cert.validity.not_after.to_double()),
    "alg": Json::string(algorithm_name(cert.alg)),
    "key": Json::string(key_name(cert.spki)),
    "sans": Json::array(names),
    "ca": Json::boolean(cert.exts.ca),
  })
}

///|
/// A name as a reader says it: the common name, with the organization beside it when it has one.
fn label(name : @x509.Name) -> String {
  match (name.cn(), name.get("2.5.4.10")) {
    (Some(c), Some(o)) => c + " (" + o + ")"
    (Some(c), None) => c
    (None, Some(o)) => o
    (None, None) => "(no name)"
  }
}

///|
fn show_name(name : @x509.GeneralName) -> String {
  match name {
    Dns(s) => "DNS:" + s
    Email(s) => "email:" + s
    Uri(s) => "URI:" + s
    Ip(a) => "IP:" + address(a)
    Dir(n) => "dir:" + label(n)
    Named(kind, _) => "form \{kind}"
  }
}

///|
/// An address as text: four octets dotted, sixteen in eight groups of four hex digits. Only the two
/// lengths an iPAddress has.
fn address(bytes : Bytes) -> String {
  if bytes.length() == 4 {
    return "\{bytes[0].to_int()}.\{bytes[1].to_int()}.\{bytes[2].to_int()}.\{bytes[3].to_int()}"
  }
  let out = StringBuilder()
  for i in 0..<8 {
    if i > 0 {
      out.write_string(":")
    }
    out.write_string(
      hex16(bytes[2 * i].to_int() * 256 + bytes[2 * i + 1].to_int()),
    )
  }
  out.to_string()
}

///|
/// Four hex digits, lower case.
fn hex16(n : Int32) -> String {
  let digits = "0123456789abcdef"
  let out = StringBuilder()
  for shift in [12, 8, 4, 0] {
    let d = n / (1 << shift) % 16
    out.write_string(digits[d:d + 1].to_owned())
  }
  out.to_string()
}

///|
/// The signature algorithm as a name rather than an OID, for the ones a certificate here can carry.
fn algorithm_name(oid : String) -> String {
  match oid {
    "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256"
    "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384"
    "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512"
    "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption"
    "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption"
    "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption"
    "1.2.840.113549.1.1.10" => "RSASSA-PSS"
    "1.3.101.112" => "Ed25519"
    "2.16.840.1.101.3.4.3.17" => "ML-DSA-44"
    "2.16.840.1.101.3.4.3.18" => "ML-DSA-65"
    "2.16.840.1.101.3.4.3.19" => "ML-DSA-87"
    o => o
  }
}

///|
/// The public key as a reader says it: the algorithm and its size.
fn key_name(spki : @x509.Spki) -> String {
  let key = spki.key() catch { _ => return "algorithm " + spki.alg }
  match key {
    Rsa(k) => "RSA \{k.size() * 8}"
    Ec(k) => "ECDSA \{k.curve().size() * 8}"
    Ed25519(_) => "Ed25519"
    MlDsa(k) =>
      match k.kind() {
        D44 => "ML-DSA-44"
        D65 => "ML-DSA-65"
        D87 => "ML-DSA-87"
      }
  }
}

///|
/// What a token refusal says, in the words the caller needs.
fn line_of(e : @jwt.Refused) -> String {
  match e {
    Shape(m) => "the token has the wrong shape: " + m
    Algorithm(want~, got~) => "the token is \{got}, not \{want}"
    Signature => "the signature does not verify under this secret"
    Expired(at~) => "the token expired at \{at.to_int()}"
    TooEarly(at~) => "the token is valid only from \{at.to_int()}"
    Issuer(want~, got~) => "issued by \{got}, not \{want}"
    Audience(_) => "the token names another audience"
    Subject(want~, got~) => "about \{got}, not \{want}"
    IssuedAt(at~) => "issued at \{at.to_int()}, too late to be trusted"
    Type(want~, got~) => "typed \{got}, not \{want}"
    Missing(claim~) => "the claim " + claim + " is missing"
    Encoding(want~, got~) =>
      "the payload is \{if want { "encoded" } else { "raw" }}, not \{if got { "encoded" } else { "raw" }}"
    Critical(name~) =>
      "the header names a critical parameter \{name} this reader does not know"
  }
}

///|
/// Why a chain was refused, as a name and the position it is about.
fn refusal(e : @x509.Refused) -> (String, Int32?) {
  match e {
    Malformed(at~, _) => ("Malformed", Some(at))
    Expired(at~) => ("Expired", Some(at))
    Premature(at~) => ("Premature", Some(at))
    Authority(at~) => ("Authority", Some(at))
    Signature(at~) => ("Signature", Some(at))
    Host(_) => ("Host", None)
    Purpose(at~) => ("Purpose", Some(at))
    Critical(at~, ..) => ("Critical", Some(at))
    Constraint(at~, ..) => ("Constraint", Some(at))
    Algorithm(at~, ..) => ("Algorithm", Some(at))
    Weak(at~) => ("Weak", Some(at))
    KeyUsage(at~) => ("KeyUsage", Some(at))
    Depth(_) => ("Depth", None)
    Budget(_) => ("Budget", None)
    Comparisons(_) => ("Comparisons", None)
    Issuer => ("Issuer", None)
  }
}

///|
fn at_reason(code : String, at : Int32?, text : String) -> Json {
  let fields : Map[String, Json] = {
    "code": Json::string(code),
    "text": Json::string(text),
  }
  if at is Some(n) {
    fields["at"] = Json::number(n.to_double())
  }
  Json::object(fields)
}

///|
fn entry(name : String, value : Json) -> Json {
  Json::object({
    "name": Json::string(name),
    // A string is shown as itself; anything else keeps its JSON, which is how a nested claim
    // reads at all.
    "value": Json::string(
      match value {
        String(text) => text
        other => @json.dumps(other)
      },
    ),
  })
}

///|
fn empty_report(kind : String, line : String) -> String {
  @json.dumps(
    Json::object({
      "kind": Json::string(kind),
      "certs": Json::array([]),
      "header": Json::array([]),
      "claims": Json::array([]),
      "verdict": refusal_verdict(line, "Shape", None),
    }),
  )
}

///|
fn refusal_verdict(line : String, code : String, at : Int64?) -> Json {
  let reason : Map[String, Json] = {
    "code": Json::string(code),
    "text": Json::string(line),
  }
  if at is Some(n) {
    reason["at"] = Json::number(n.to_double())
  }
  Json::object({
    "ok": Json::boolean(false),
    "line": Json::string(line),
    "path": Json::array([]),
    "reason": Json::object(reason),
  })
}

///|
fn refusal_report(
  kind : String,
  line : String,
  code : String,
  at : Int64?,
  shown : Array[Json],
  body : Array[Json],
) -> String {
  @json.dumps(
    Json::object({
      "kind": Json::string(kind),
      "certs": Json::array(shown),
      "header": Json::array(shown),
      "claims": Json::array(body),
      "verdict": refusal_verdict(line, code, at),
    }),
  )
}

///|
fn join(items : Array[String]) -> String {
  let out = StringBuilder()
  for i, item in items {
    if i > 0 {
      out.write_string(" → ")
    }
    out.write_string(item)
  }
  out.to_string()
}
