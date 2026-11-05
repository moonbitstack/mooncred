// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// One case, judged: build the chain and the anchors, call `x509.verify` with the
// purpose, the time and the name the case asks for, and compare the outcome with the
// one limbo states. A chain that does not even read counts as a refusal, which is what
// a validator does with it.

///|
priv enum Verdict {
  Agreed
  Disagreed(String)
  Unsupported(String)
}

///|
fn judge(c : Case) -> Verdict {
  guard c.unsupported is None else {
    return Unsupported(c.unsupported.unwrap())
  }
  // An anchor this validator cannot read is one it cannot trust: the chain is refused, not
  // left unjudged.
  let anchors = match ders(c.anchors) {
    Some(list) => list
    None => return conclude(c, false, "a trust anchor does not read")
  }
  let roots = @x509.Roots::new(certs=anchors[:]) catch {
    _ => return conclude(c, false, "a trust anchor does not read")
  }
  let chain = match chain_ders(c) {
    Some(list) => list
    None =>
      return conclude(c, false, "a certificate in the chain does not read")
  }
  let at = match c.at {
    Some(seconds) => seconds
    None =>
      match instant(chain) {
        Some(seconds) => seconds
        None => return conclude(c, false, "no certificate in the chain reads")
      }
  }
  let policy = match c.depth {
    Some(d) => @x509.Policy::new(usage=c.usage, depth=d)
    None => @x509.Policy::new(usage=c.usage)
  }
  match c.names {
    [] =>
      match attempt(chain, roots, at, None, policy) {
        Ok(_) => conclude(c, true, "")
        Err(why) => conclude(c, false, why)
      }
    [(_, value)] =>
      match attempt(chain, roots, at, Some(value), policy) {
        Ok(_) => conclude(c, true, "")
        Err(why) => conclude(c, false, why)
      }
    names =>
      // A server holds its client to the names it knows it accepts: any one will do.
      match attempt(chain, roots, at, None, policy) {
        Ok(path) =>
          if names.iter().any(fn(n) { path[0].matches(n.1) }) {
            conclude(c, true, "")
          } else {
            conclude(c, false, "the leaf names none of " + show(names))
          }
        Err(why) => conclude(c, false, why)
      }
  }
}

///|
/// A case that names no time is judged at the moment the chain itself settles on: the
/// latest notBefore among its certificates, which is inside every window when the case
/// is about the shape of the path rather than its dates.
fn instant(chain : Array[Bytes]) -> Int64? {
  let mut at : Int64? = None
  for der in chain {
    let cert = @x509.parse(der[:]) catch { _ => continue }
    let not_before = cert.validity.not_before
    at = match at {
      Some(kept) => Some(if kept > not_before { kept } else { not_before })
      None => Some(not_before)
    }
  }
  at
}

///|
fn conclude(c : Case, accepted : Bool, why : String) -> Verdict {
  if accepted == c.expected {
    Agreed
  } else if accepted {
    Disagreed("accepted a chain limbo refuses")
  } else {
    Disagreed("refused a chain limbo accepts: " + why)
  }
}

///|
fn show(names : Array[(String, String)]) -> String {
  names.map(fn(n) { n.0 + ":" + n.1 }).join(", ")
}

///|
fn attempt(
  chain : Array[Bytes],
  roots : @x509.Roots,
  at : Int64,
  host : String?,
  policy : @x509.Policy,
) -> Result[Array[@x509.Cert], String] {
  match host {
    Some(h) =>
      Ok(@x509.verify(chain[:], roots, now=at, host=h, policy~)) catch {
        e => Err(e.to_string())
      }
    None =>
      Ok(@x509.verify(chain[:], roots, now=at, policy~)) catch {
        e => Err(e.to_string())
      }
  }
}

///|
fn ders(pems : Array[String]) -> Array[Bytes]? {
  let out = []
  for pem in pems {
    guard one_der(pem) is Some(der) else { return None }
    out.push(der)
  }
  Some(out)
}

///|
fn chain_ders(c : Case) -> Array[Bytes]? {
  guard one_der(c.leaf) is Some(leaf) else { return None }
  let out = [leaf]
  for pem in c.intermediates {
    guard one_der(pem) is Some(der) else { return None }
    out.push(der)
  }
  Some(out)
}

///|
fn one_der(pem : String) -> Bytes? {
  let list = @x509.pems(pem) catch { _ => return None }
  guard list.length() > 0 else { return None }
  Some(list[0])
}
