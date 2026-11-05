// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// One case of the suite, read out of the JSON limbo ships, and the decision taken
// before any chain is built: whether this validator can act on everything the case
// asks for at all.

///|
priv struct Case {
  id : String
  expected : Bool
  usage : @x509.Usage
  anchors : Array[String]
  leaf : String
  intermediates : Array[String]
  at : Int64?
  names : Array[(String, String)]
  depth : Int32?
  unsupported : String?
}

///|
fn Json::text(self : Json, name : String) -> String? {
  guard self is Object(fields) else { return None }
  match fields.get(name) {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
fn Json::texts(self : Json, name : String) -> Array[String] {
  guard self is Object(fields) else { return [] }
  match fields.get(name) {
    Some(Array(items)) =>
      items.map(fn(one) {
        match one {
          String(s) => s
          _ => ""
        }
      })
    _ => []
  }
}

///|
fn Json::count(self : Json, name : String) -> Int32 {
  self.texts(name).length()
}

///|
fn Json::integer(self : Json, name : String) -> Int32? {
  guard self is Object(fields) else { return None }
  match fields.get(name) {
    Some(Number(d, ..)) => Some(d.to_int())
    _ => None
  }
}

///|
/// A name the case asks the leaf to carry: the kind it is written in and the text.
fn Json::names(self : Json, name : String) -> Array[(String, String)] {
  guard self is Object(fields) else { return [] }
  let out = []
  for entry in [fields.get(name)] {
    match entry {
      Some(Object(one)) =>
        if one.get("kind") is Some(String(kind)) &&
          one.get("value") is Some(String(value)) {
          out.push((kind, value))
        }
      Some(Array(items)) =>
        for item in items {
          if item is Object(one) &&
            one.get("kind") is Some(String(kind)) &&
            one.get("value") is Some(String(value)) {
            out.push((kind, value))
          }
        }
      _ => ()
    }
  }
  out
}

///|
fn Json::time(self : Json) -> Int64? {
  guard self.text("validation_time") is Some(text) else { return None }
  let moment = @moondate.of_isoformat(text) catch { _ => return None }
  moment.epoch()
}

///|
/// The purpose a name in `extended_key_usage` asks for. limbo writes those as well-known
/// names or as dotted OIDs; both come to the same thing here.
fn purpose(name : String) -> @x509.Usage? {
  match name {
    "serverAuth" => Some(@x509.Usage::Server)
    "clientAuth" => Some(@x509.Usage::Client)
    "anyExtendedKeyUsage" => Some(@x509.Usage::Any)
    "codeSigning" => Some(@x509.Usage::Other("1.3.6.1.5.5.7.3.3"))
    "emailProtection" => Some(@x509.Usage::Other("1.3.6.1.5.5.7.3.4"))
    "timeStamping" => Some(@x509.Usage::Other("1.3.6.1.5.5.7.3.8"))
    "OCSPSigning" => Some(@x509.Usage::Other("1.3.6.1.5.5.7.3.9"))
    _ =>
      if name.length() > 0 &&
        name.split(".").all(fn(part) { part.length() > 0 }) {
        Some(@x509.Usage::Other(name))
      } else {
        None
      }
  }
}

///|
fn Case::read(json : Json) -> Case? {
  guard json.text("id") is Some(id) else { return None }
  let names = json.names("expected_peer_name") +
    json.names("expected_peer_names")
  let eku = json.texts("extended_key_usage")
  let mut unsupported : String? = None
  let usage = match eku {
    [] =>
      if json.text("validation_kind") == Some("CLIENT") {
        @x509.Usage::Client
      } else {
        @x509.Usage::Server
      }
    [one] =>
      match purpose(one) {
        Some(u) => u
        None => {
          unsupported = Some("a purpose written as something other than an OID")
          @x509.Usage::Any
        }
      }
    _ => {
      unsupported = Some("more than one extended key usage")
      @x509.Usage::Any
    }
  }
  if json.count("crls") > 0 {
    unsupported = Some("a revocation list, which `verify` does not take")
  }
  if json.count("key_usage") > 0 {
    unsupported = Some("a key-usage constraint on the leaf")
  }
  if json.count("signature_algorithms") > 0 {
    unsupported = Some("a signature-algorithm constraint")
  }
  if names.iter().any(fn(n) { n.0 != "DNS" && n.0 != "IP" }) {
    unsupported = Some("a peer name that is neither a DNS name nor an address")
  }
  let at = json.time()
  Some({
    id,
    expected: json.text("expected_result") == Some("SUCCESS"),
    usage,
    anchors: json.texts("trusted_certs"),
    leaf: json.text("peer_certificate").unwrap_or(""),
    intermediates: json.texts("untrusted_intermediates"),
    at,
    names,
    depth: json.integer("max_chain_depth"),
    unsupported,
  })
}
