// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The DER inside a PEM envelope (RFC 7468).
///
/// Everything outside the `-----BEGIN ...-----` and `-----END ...-----` lines
/// is dropped and the rest is base64-decoded. The label is not checked: what
/// the octets are is the caller's question, and a `CERTIFICATE` and a
/// `PUBLIC KEY` reach different readers from here.
///
/// Whitespace inside the body is ignored, which is what RFC 7468 §2 asks of a
/// parser and what makes a CRLF file read the same as an LF one.
pub fn pem(text : String) -> Bytes raise @asn1.Refused {
  let body = StringBuilder()
  let mut opened = false
  let mut closed = false
  for line in text.split("\n") {
    let l = line.to_owned()
    if l.has_prefix("-----BEGIN") {
      opened = true
    } else if l.has_prefix("-----END") {
      closed = true
      break
    } else if opened {
      body.write_string(l)
    }
  }
  if !opened || !closed {
    raise @asn1.Malformed("not a PEM envelope")
  }
  let der = @base64.decode_lossy(body.to_string())
  if der.length() == 0 {
    raise @asn1.Malformed("PEM envelope carries no DER")
  }
  der
}

///|
/// The PEM envelope around DER (RFC 7468 §2): the label, the base64 body broken at sixty-four
/// columns, and the closing line. What this writes, `openssl` reads — the line length and the
/// trailing newline are the parts a strict reader notices.
pub fn pem_wrap(der : BytesView, label~ : String = "CERTIFICATE") -> String {
  let text = @base64.encode(der)
  let out = StringBuilder()
  out.write_string("-----BEGIN " + label + "-----\n")
  let mut i = 0
  while i < text.length() {
    let end = if i + 64 < text.length() { i + 64 } else { text.length() }
    out.write_string(text[i:end].to_owned())
    out.write_string("\n")
    i = end
  }
  out.write_string("-----END " + label + "-----\n")
  out.to_string()
}

///|
/// The DER of every PEM envelope in `text` with the label `label`, in order — a CA bundle such
/// as `ca-certificates.crt` or curl's `cacert.pem` is a run of `CERTIFICATE` envelopes with prose
/// between them. Envelopes with another label are passed over.
pub fn pems(
  text : String,
  label~ : String = "CERTIFICATE",
) -> Array[Bytes] raise @asn1.Refused {
  let out : Array[Bytes] = []
  let opening = "-----BEGIN " + label + "-----"
  let closing = "-----END " + label + "-----"
  let mut body = StringBuilder()
  let mut inside = false
  for line in text.split("\n") {
    let l = line.trim_end(chars=" \t\r").to_owned()
    if !inside {
      if l == opening {
        inside = true
        body = StringBuilder()
      }
    } else if l == closing {
      let der = @base64.decode(body.to_string()) catch {
        _ => raise @asn1.Malformed("PEM body is not base64")
      }
      if der.length() == 0 {
        raise @asn1.Malformed("PEM envelope carries no DER")
      }
      out.push(der)
      inside = false
    } else if l.has_prefix("-----") {
      raise @asn1.Malformed("PEM envelope is not closed")
    } else {
      body.write_string(l.trim(chars=" \t").to_owned())
    }
  }
  if inside {
    raise @asn1.Malformed("PEM envelope is not closed")
  }
  out
}
