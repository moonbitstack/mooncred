// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A JWS is octets and the signatures over them; a JWT is a claims set that happens to travel
// in one. `sign` and `verify` in jwt.mbt are the second; this file is the first, with the two
// things a claims set never needs: a payload that is not JSON and is not even encoded
// (RFC 7797), and a JSON serialisation that can carry several signatures over one payload.

///|
/// One signature over a payload, as the JSON serialisations of RFC 7515 §7.2 carry it.
///
/// `protected` is the base64url text that was signed, kept as text rather than decoded: a
/// verifier must hash exactly the octets that arrived, and re-encoding a decoded header is how
/// a message that verified somewhere else fails here.
pub(all) struct Signature {
  /// The protected header, base64url. `None` when the signature protects no header, which
  /// RFC 7515 §A.5 allows and RFC 7520 §4.7 uses; the signing input then begins with a dot.
  signed : String?
  /// The header that travels unauthenticated beside the signature.
  header : Map[String, Json]?
  /// The signature itself, base64url.
  signature : String
}

///|
/// A payload and the signatures over it (RFC 7515 §7.2).
///
/// The payload is octets: a claims set, a document, a file. It is `None` only for a message
/// whose payload travels beside it — RFC 7515 §A.5 — in which case a verifier is given the
/// octets to check against.
///
/// Every signature in one message sees the payload the same way. A message whose first
/// signature says the payload is base64url and whose second says it is not describes two
/// different payloads in one member, so `Message::sign` refuses the second.
pub struct Message {
  payload : Bytes?
  signatures : Array[Signature]
  encoded : Bool
}

///|
/// Start a message over a payload, with no signatures yet.
pub fn Message::new(payload : BytesView) -> Message {
  { payload: Some(payload.to_owned()), signatures: [], encoded: true, }
}

///|
/// The payload, or `None` for a message that carries it beside the text.
pub fn Message::payload(self : Message) -> Bytes? {
  self.payload
}

///|
/// The signatures, in the order they were added.
pub fn Message::signatures(self : Message) -> Array[Signature] {
  self.signatures
}

///|
/// Whether the payload travels base64url encoded. `false` is RFC 7797's `b64: false`.
pub fn Message::encoded(self : Message) -> Bool {
  self.encoded
}

///|
/// The same message with its payload left out, for a caller that sends the octets by another
/// road and wants the signature to cover them anyway.
pub fn Message::detached(self : Message) -> Message {
  { ..self, payload: None, }
}

///|
/// Add a signature by this key under this algorithm, and return the message.
///
/// `signed` is the header that is signed and `header` the one that is not; `alg` goes into the
/// signed one. `bare` is RFC 7515 §A.5's "protecting content only": no signed header at all,
/// with `alg` and everything else in the unprotected one. That form authenticates the payload
/// and nothing about how to read it, so the reader of one must still be told which algorithm
/// and key to try — which is the only reason it is safe enough to offer.
///
/// The two headers of one signature may not name the same parameter twice.
pub fn Message::sign(
  self : Message,
  alg : Alg,
  key : &@spec.Signer,
  signed~ : Map[String, Json] = Map([]),
  header~ : Map[String, Json] = Map([]),
  b64~ : Bool = true,
  bare~ : Bool = false,
) -> Message raise Refused {
  guard self.payload is Some(payload) else {
    raise Shape("a detached message has no payload to sign")
  }
  if self.signatures.length() > 0 && b64 != self.encoded {
    raise Shape("one message carries one payload, encoded one way")
  }
  if bare && !b64 {
    raise Shape("b64 has to be signed, so a bare signature is an encoded one")
  }
  if bare {
    for name, _ in signed {
      raise Shape("\{name} belongs in the header of a bare signature")
    }
  }
  for name, _ in signed {
    if name == "alg" || name == "b64" || name == "crit" {
      raise Shape("\{name} is written by the signer, not by the caller")
    }
    if header.get(name) is Some(_) {
      raise Shape("\{name} is in both headers of one signature")
    }
  }
  for name, _ in header {
    if !bare && name == "alg" {
      raise Shape("alg belongs in the header that is signed")
    }
  }
  let head : Map[String, Json] = Map([])
  if !bare {
    head["alg"] = Json::string(alg.name())
  }
  for name, value in signed {
    head[name] = value
  }
  if !b64 {
    head["b64"] = Json::boolean(false)
    head["crit"] = Json::array([Json::string("b64")])
  }
  let encoded_head = b64_of(@utf8.encode(@json.dumps(Json::object(head)))[:])
  let made = if bare {
    key.sign(signing_input("", payload, b64))
  } else {
    key.sign(signing_input(encoded_head, payload, b64))
  }
  let loose_fields : Map[String, Json] = Map([])
  if bare {
    loose_fields["alg"] = Json::string(alg.name())
  }
  let mut loose_count = 0
  for name, value in header {
    loose_count += 1
    loose_fields[name] = value
  }
  let loose : Map[String, Json]? = if loose_count > 0 || bare {
    Some(loose_fields)
  } else {
    None
  }
  let appended : Array[Signature] = []
  for one in self.signatures {
    appended.push(one)
  }
  appended.push({
    signed: if bare {
      None
    } else {
      Some(encoded_head)
    },
    header: loose,
    signature: b64_of(made[:]),
  })
  { payload: self.payload, signatures: appended, encoded: b64, }
}

///|
/// The message as the general JSON serialisation: a payload and an array of signatures.
pub fn Message::json(self : Message) -> Json raise Refused {
  let signatures : Array[Json] = []
  for one in self.signatures {
    let entry : Map[String, Json] = Map([])
    match one.signed {
      Some(text) => entry["protected"] = Json::string(text)
      None => ()
    }
    match one.header {
      Some(fields) => entry["header"] = Json::object(fields)
      None => ()
    }
    entry["signature"] = Json::string(one.signature)
    signatures.push(Json::object(entry))
  }
  let out : Map[String, Json] = Map([])
  match payload_member(self) {
    Some(value) => out["payload"] = value
    None => ()
  }
  out["signatures"] = Json::array(signatures)
  Json::object(out)
}

///|
/// The message as the flattened serialisation: one signature, its members beside the payload.
///
/// This is a convenience for the one-signature case, and a refusal for any other, because the
/// flattened form has nowhere to put a second signature.
pub fn Message::flattened(self : Message) -> Json raise Refused {
  guard self.signatures.length() == 1 else {
    raise Shape("the flattened serialisation carries exactly one signature")
  }
  let one = self.signatures[0]
  let out : Map[String, Json] = Map([])
  match payload_member(self) {
    Some(value) => out["payload"] = value
    None => ()
  }
  match one.signed {
    Some(text) => out["protected"] = Json::string(text)
    None => ()
  }
  match one.header {
    Some(fields) => out["header"] = Json::object(fields)
    None => ()
  }
  out["signature"] = Json::string(one.signature)
  Json::object(out)
}

///|
/// Sign octets into the compact serialisation.
///
/// `b64` is RFC 7797: `false` signs the payload itself instead of a base64url copy of it, so a
/// token can carry octets that must arrive as they were signed. With `false` the payload must
/// be ASCII and must not contain a dot, because the compact form is cut at its dots.
///
/// `detached` signs the payload without carrying it (RFC 7515 §A.5): the middle segment is
/// empty and the octets travel by another road, to be handed to `verify_bytes` by the caller.
pub fn sign_bytes(
  payload : BytesView,
  alg : Alg,
  key : &@spec.Signer,
  b64~ : Bool = true,
  typ? : String,
  extra~ : Map[String, Json] = Map([]),
  detached~ : Bool = false,
) -> String raise Refused {
  for name, _ in extra {
    if name == "alg" || name == "b64" || name == "crit" || name == "typ" {
      raise Shape("\{name} is written by the signer, not by the caller")
    }
  }
  let head : Map[String, Json] = Map([])
  head["alg"] = Json::string(alg.name())
  match typ {
    Some(kind) => head["typ"] = Json::string(kind)
    None => ()
  }
  for name, value in extra {
    head[name] = value
  }
  if !b64 {
    head["b64"] = Json::boolean(false)
    head["crit"] = Json::array([Json::string("b64")])
  }
  let encoded_head = b64_of(@utf8.encode(@json.dumps(Json::object(head)))[:])
  let made = key.sign(signing_input(encoded_head, payload, b64))
  let carried = if detached { "" } else { payload_text(payload, b64) }
  encoded_head + "." + carried + "." + b64_of(made[:])
}

///|
/// Verify a compact JWS and return its payload octets.
///
/// `b64` says how the caller expects the payload to travel, and a token that says otherwise is
/// refused: RFC 7797 §6 makes the choice part of what is signed precisely so that two readers
/// cannot disagree about which octets the signature covered.
///
/// `payload` is for a token that carries no payload of its own: the octets arrive from
/// wherever the sender put them, and the signature is checked against those.
pub fn verify_bytes(
  token : StringView,
  alg : Alg,
  key : &@spec.Verifier,
  b64~ : Bool = true,
  payload? : Bytes,
) -> Bytes raise Refused {
  let (first, second) = dots(token)
  let head = object(token[0:first], "header")
  let named = match head.get("alg") {
    Some(String(name)) => name
    _ => raise Shape("the header names no algorithm")
  }
  let encoded = b64_of_header(head)
  if named != alg.name() {
    raise Algorithm(want=alg.name(), got=named)
  }
  if encoded != b64 {
    raise Encoding(want=b64, got=encoded)
  }
  let carried = match payload {
    Some(given) => given
    None =>
      if b64 {
        unwrap(token[first + 1:second], "payload")
      } else {
        @utf8.encode(token[first + 1:second])
      }
  }
  let given = unwrap(token[second + 1:], "signature")
  if !key.verify(
      signing_input(token[0:first].to_owned(), carried[:], b64),
      given[:],
    ) {
    raise Signature
  }
  carried
}

///|
/// What a caller is willing to accept: one algorithm and the key that checks it.
///
/// A message may carry several signatures by different keys under different algorithms; each
/// check is tried against the signatures that name its algorithm, and one that verifies ends
/// the search. Nothing is tried that the caller did not offer, so a signature added under an
/// algorithm this program happens to link is not a way in.
pub(all) struct Check {
  alg : Alg
  key : &@spec.Verifier
}

///|
pub fn Check::new(alg : Alg, key : &@spec.Verifier) -> Check {
  { alg, key, }
}

///|
/// A payload that one of the checks accepted.
pub(all) struct Verified {
  /// The octets the signature covered.
  payload : Bytes
  /// Which signature of the message verified, counting from zero.
  index : Int32
  /// The headers of that signature: the protected one and the unprotected one together.
  header : Map[String, Json]
}

///|
/// Verify a JSON serialisation — general or flattened, it is told apart by its shape — and
/// return the payload that one of the checks accepted.
///
/// `payload` is for a message whose payload travels beside the text: RFC 7515 §A.5 leaves the
/// member out, and the octets come from the caller that sent it. A message that carries its
/// own payload and a caller that supplies one are a disagreement, and are refused.
pub fn verify_json(
  text : StringView,
  checks~ : Array[Check],
  payload? : Bytes,
) -> Verified raise Refused {
  let members = document(text)
  let entries = signatures_of(members)
  let carried = payload_of(members)
  let octets = match (carried, payload) {
    (Some((octets, _)), None) => octets
    (None, Some(given)) => given
    (None, None) =>
      raise Shape("the message carries no payload and none was given")
    (Some(_), Some(_)) =>
      raise Shape("the message carries a payload and one was given beside it")
  }
  let encoded = match carried {
    Some((_, encoded)) => encoded
    None => encoded_of(entries[0])
  }
  let mut at = 0
  for one in entries {
    let (_, merged) = headers_of(one)
    let named = algorithm_of(merged)
    let says = encoded_of(one)
    if says != encoded {
      raise Encoding(want=encoded, got=says)
    }
    for check in checks {
      if check.alg.name() == named {
        let input = signing_input(
          match one.signed {
            Some(encoded_head) => encoded_head
            None => ""
          },
          octets[:],
          encoded,
        )
        let given = unwrap(one.signature[:], "signature")
        if check.key.verify(input, given[:]) {
          return { payload: octets, index: at, header: merged, }
        }
      }
    }
    at += 1
  }
  raise Signature
}

///|
/// A JSON serialisation read as a message, without checking anything.
///
/// The signatures are read and the payload is decoded; nothing is verified. This is what a
/// caller uses to look at `kid` and decide which keys to offer, and for nothing else.
pub fn message(text : StringView) -> Message raise Refused {
  let members = document(text)
  let entries = signatures_of(members)
  let carried = payload_of(members)
  let payload = match carried {
    Some((octets, _)) => Some(octets)
    None => None
  }
  let encoded = match carried {
    Some((_, encoded)) => encoded
    None => encoded_of(entries[0])
  }
  { payload, signatures: entries, encoded, }
}

// ----------------------------------------------------------------- the pieces

///|
/// The signing input of RFC 7515 §5.1 and RFC 7797 §3: the header, a dot, and the payload as it
/// travels. Octets rather than text, because the payload under RFC 7797 is whatever the signer
/// was given, and `head ++ 0x2e ++ payload` is the definition whether or not it is UTF-8.
fn signing_input(head : String, payload : BytesView, b64 : Bool) -> Bytes {
  let out = Buffer()
  out.write_bytes(@utf8.encode(head)[:])
  out.write_byte(0x2E)
  if b64 {
    out.write_bytes(@utf8.encode(b64_of(payload))[:])
  } else {
    out.write_bytesview(payload)
  }
  out.to_bytes()
}

///|
/// The payload as it appears in a token that carries it: base64url, or the octets themselves.
///
/// An unencoded payload in that position has to be ASCII and has to contain no dot — the
/// compact form is cut at its dots, and its other two segments are ASCII. A payload that
/// violates either travels beside the token instead, which is what RFC 7797 §4 shows.
fn payload_text(payload : BytesView, b64 : Bool) -> String raise Refused {
  if b64 {
    return b64_of(payload)
  }
  for i in 0..<payload.length() {
    let octet = payload[i].to_int()
    if octet == 0x2E {
      raise Shape("an unencoded payload cannot contain a dot")
    }
    if octet >= 0x80 {
      raise Shape("an unencoded payload in the compact form is ASCII")
    }
  }
  @utf8.decode(payload) catch {
    _ => raise Shape("an unencoded payload is not text")
  }
}

///|
/// The two headers of one signature, kept apart and together.
///
/// RFC 7515 §5.2 requires the two to name no parameter twice: a reader that takes one of the
/// two values when a message gives both has been told two things and believes one of them.
fn headers_of(
  one : Signature,
) -> (Map[String, Json], Map[String, Json]) raise Refused {
  let own = protected_fields(one)
  let merged : Map[String, Json] = Map([])
  for name, value in own {
    merged[name] = value
  }
  match one.header {
    Some(extra) =>
      for name, value in extra {
        if merged.get(name) is Some(_) {
          raise Shape("\{name} is in both headers of one signature")
        }
        if name == "b64" || name == "crit" {
          raise Shape("\{name} has to be in the header that is signed")
        }
        merged[name] = value
      }
    None => ()
  }
  (own, merged)
}

///|
/// The algorithm a header names.
fn algorithm_of(merged : Map[String, Json]) -> String raise Refused {
  match merged.get("alg") {
    Some(String(name)) => name
    _ => raise Shape("the header names no algorithm")
  }
}

///|
/// The `b64` one signature states, with its `crit` checked on the way (RFC 7797 defaults it to
/// true).
///
/// A `crit` naming anything but `b64` is refused: RFC 7515 §4.1.11 says a reader that does not
/// understand a critical parameter must not accept the signature, and this reader understands
/// exactly one.
fn encoded_of(one : Signature) -> Bool raise Refused {
  b64_of_header(protected_fields(one))
}

///|
fn protected_fields(one : Signature) -> Map[String, Json] raise Refused {
  match one.signed {
    Some(text) => object(text[:], "protected header")
    None => Map([])
  }
}

///|
fn b64_of_header(own : Map[String, Json]) -> Bool raise Refused {
  match own.get("crit") {
    Some(Array(items)) =>
      for item in items {
        match item {
          String(name) => if name != "b64" { raise Critical(name~) }
          _ => raise Shape("crit is an array of strings")
        }
      }
    Some(_) => raise Shape("crit is an array of strings")
    None => ()
  }
  match own.get("b64") {
    Some(True) => true
    Some(False) => false
    Some(_) => raise Shape("b64 is a boolean")
    None => true
  }
}

///|
/// The signatures of a general or flattened serialisation, in the order they appear.
fn signatures_of(members : Map[String, Json]) -> Array[Signature] raise Refused {
  let out : Array[Signature] = []
  match members.get("signatures") {
    Some(Array(items)) =>
      for item in items {
        out.push(signature_of(item))
      }
    Some(_) => raise Shape("signatures is an array")
    None =>
      match members.get("signature") {
        Some(_) => out.push(signature_of(Json::object(members)))
        None =>
          raise Shape("a JWS JSON serialisation has signatures or a signature")
      }
  }
  out
}

///|
fn signature_of(value : Json) -> Signature raise Refused {
  let fields = match value {
    Object(fields) => fields
    _ => raise Shape("a signature is a JSON object")
  }
  let text = match fields.get("signature") {
    Some(String(text)) => text
    _ => raise Shape("a signature carries no signature")
  }
  let header = match fields.get("header") {
    Some(Object(header)) => Some(header)
    Some(_) => raise Shape("header is a JSON object")
    None => None
  }
  {
    signed: match fields.get("protected") {
      Some(String(text)) => Some(text)
      Some(_) => raise Shape("protected is a string")
      None => None
    },
    header,
    signature: text,
  }
}

///|
/// The payload member, and whether it travels encoded.
///
/// Whether it is base64url is not a property of the member but of the signature over it: the
/// protected header of each signature says, and RFC 7515 §5.2 requires them all to agree.
fn payload_of(members : Map[String, Json]) -> (Bytes, Bool)? raise Refused {
  let text = match members.get("payload") {
    Some(String(text)) => text
    Some(_) => raise Shape("payload is a string")
    None => return None
  }
  if encoded_of(signatures_of(members)[0]) {
    Some((unwrap(text[:], "payload"), true))
  } else {
    Some((@utf8.encode(text), false))
  }
}

///|
fn document(text : StringView) -> Map[String, Json] raise Refused {
  let value = @json.loads(text) catch { _ => raise Shape("not valid JSON") }
  match value {
    Object(members) => members
    _ => raise Shape("a JWS JSON serialisation is a JSON object")
  }
}

///|
/// The payload member of a message, written the way the message says it travels.
///
/// In a JSON serialisation the payload is a member of a JSON object, so an unencoded one has to
/// be text — a dot is not a problem here, the object is not cut at its dots — and octets that
/// are not UTF-8 travel encoded or not at all.
fn payload_member(message : Message) -> Json? raise Refused {
  match message.payload {
    Some(octets) =>
      if message.encoded {
        Some(Json::string(b64_of(octets[:])))
      } else {
        Some(
          Json::string(
            @utf8.decode(octets) catch {
              _ =>
                raise Shape("an unencoded payload in JSON has to be UTF-8 text")
            },
          ),
        )
      }
    None => None
  }
}

///|
/// Where the two dots are, allowing an empty payload for a detached signature.
fn dots(token : StringView) -> (Int32, Int32) raise Refused {
  let mut first = -1
  let mut second = -1
  let mut count = 0
  for i in 0..<token.length() {
    if token.at(i).to_int() == 0x2E {
      count += 1
      if first < 0 {
        first = i
      } else if second < 0 {
        second = i
      }
    }
  }
  if count != 2 || first == 0 || second == token.length() - 1 {
    raise Shape("a compact JWS is three dot-separated segments")
  }
  (first, second)
}

///|
fn b64_of(raw : BytesView) -> String {
  @base64.encode(raw, kind=Url, padding=false)
}
