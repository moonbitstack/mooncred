// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn ip_literal(s : String) -> Bytes? {
  let t = match s.strip_prefix("[") {
    Some(rest) =>
      match rest.strip_suffix("]") {
        Some(inner) => inner.to_owned()
        None => return None
      }
    None => s
  }
  if t.contains(":") {
    ipv6(t)
  } else {
    ipv4(t)
  }
}

///|
/// A dotted-quad: four decimal octets, no leading zeros (a leading zero reads as octal in some
/// parsers, so accepting one would let two readers see two addresses).
fn ipv4(s : String) -> Bytes? {
  let parts = s.split(".").to_array()
  if parts.length() != 4 {
    return None
  }
  let out : Array[Byte] = []
  for p in parts {
    if p.length() == 0 ||
      p.length() > 3 ||
      (p.length() > 1 && p.has_prefix("0")) {
      return None
    }
    let mut n = 0
    for c in p {
      if c < '0' || c > '9' {
        return None
      }
      n = n * 10 + (c.to_int() - '0'.to_int())
    }
    if n > 255 {
      return None
    }
    out.push(n.to_byte())
  }
  Some(Bytes::from_array(out))
}

///|
fn hex_group(g : StringView) -> Int32? {
  if g.length() == 0 || g.length() > 4 {
    return None
  }
  let mut n = 0
  for c in g {
    let d = match c {
      '0'..<='9' => c.to_int() - '0'.to_int()
      'a'..<='f' => c.to_int() - 'a'.to_int() + 10
      'A'..<='F' => c.to_int() - 'A'.to_int() + 10
      _ => return None
    }
    n = n * 16 + d
  }
  Some(n)
}

///|
/// An IPv6 literal: eight groups, one `::` standing for a run of zero groups, and an optional
/// dotted-quad in the last thirty-two bits. A zone identifier (`%eth0`) names an interface, not
/// an address a certificate can carry, so it is refused.
fn ipv6(s : String) -> Bytes? {
  if s.contains("%") {
    return None
  }
  let halves = s.split("::").to_array()
  if halves.length() > 2 {
    return None
  }
  fn groups(part : StringView) -> Array[Int32]? {
    if part.length() == 0 {
      return Some([])
    }
    let out = []
    let pieces = part.split(":").to_array()
    for i, g in pieces {
      if i == pieces.length() - 1 && g.contains(".") {
        guard ipv4(g.to_owned()) is Some(v4) else { return None }
        out.push(v4[0].to_int() * 256 + v4[1].to_int())
        out.push(v4[2].to_int() * 256 + v4[3].to_int())
      } else {
        guard hex_group(g) is Some(n) else { return None }
        out.push(n)
      }
    }
    Some(out)
  }
  guard groups(halves[0]) is Some(head) else { return None }
  let words = if halves.length() == 2 {
    guard groups(halves[1]) is Some(tail) else { return None }
    if head.length() + tail.length() > 7 {
      return None
    }
    let zeros = Array::make(8 - head.length() - tail.length(), 0)
    head + zeros + tail
  } else {
    head
  }
  if words.length() != 8 {
    return None
  }
  let out = []
  for w in words {
    out.push((w >> 8).to_byte())
    out.push((w & 0xff).to_byte())
  }
  Some(Bytes::from_array(out))
}
