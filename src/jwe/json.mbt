// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The JSON serialisation of RFC 7516 §7.2: one payload, one content-encryption key, and one or
// more recipients, each with its own copy of that key. What the compact form cannot carry lives
// here — a second recipient, additional authenticated data that is not part of the header, and
// the choice of which header is authenticated.

///|
/// Where the two parameters that name the algorithms go.
///
/// RFC 7516 leaves this open, and the three answers are not equivalent: what is not in the
/// protected header is not authenticated. A reader takes any of them; a writer has to pick, so
/// it says which.
#derive(Eq, Debug)
pub(all) enum Layout {
  /// `enc` protected, `alg` in each recipient's header. The default, because it is the only
  /// placement under which one ciphertext can serve several recipients.
  Recipient
  /// Everything protected, as the compact form has it. Only meaningful for one recipient.
  Protected
  /// Nothing protected: the ciphertext is authenticated and nothing about it is (RFC 7520
  /// §5.12). For a message whose header has to stay readable by something that cannot verify
  /// it, and for nothing else.
  Bare
}

///|
pub extend Layout with Eq::{equal, not_equal}

///|
pub extend Layout with Debug::{to_repr}

///|
/// Seal a payload for one or more recipients, into the general JSON serialisation.
///
/// `cek` is carried per recipient and has to be the same key for all of them: the ciphertext is
/// one, and what differs between recipients is only how each of them can reach that key. Under
/// `dir` and ECDH-ES the key is derived, so those messages carry exactly one recipient.
///
/// `signed` adds parameters to the protected header and `shared` to the unprotected one; a
/// parameter the caller has already placed is not written a second time, which is how a message
/// whose `alg` travels unprotected is expressed.
pub fn seal(
  plain : BytesView,
  enc~ : Enc,
  recipients~ : Array[Recipient],
  iv~ : BytesView,
  aad~ : BytesView = b"",
  signed~ : Map[String, Json] = Map([]),
  shared~ : Map[String, Json] = Map([]),
  layout~ : Layout = Recipient,
  compress~ : Bool = false,
  policy~ : Policy = policy,
) -> Json raise Refused {
  if iv.length() != enc.iv_size() {
    raise Malformed(
      "an IV of \{iv.length()} octets for " +
      enc.name() +
      ", which wants \{enc.iv_size()}",
    )
  }
  guard recipients.length() > 0 else {
    raise Malformed("a message has at least one recipient")
  }
  let mut derived = 0
  for one in recipients {
    if one.alg.derives() {
      derived += 1
    }
  }
  if derived > 0 && recipients.length() > 1 {
    raise Malformed(
      "dir and ECDH-ES carry one recipient, because they derive the key",
    )
  }
  if layout is Layout::Protected && recipients.length() > 1 {
    raise Malformed(
      "a protected alg names one algorithm, so it names one recipient",
    )
  }
  // What the caller has already placed: a name here is not written again.
  let placed : Map[String, Json] = Map([])
  for name, value in signed {
    placed[name] = value
  }
  for name, value in shared {
    placed[name] = value
  }
  let mut content_key : Bytes? = None
  let carried : Array[(Bytes, Map[String, Json])] = []
  for one in recipients {
    let (key, wrapped, parameters) = seal_recipient(enc, one, policy)
    content_key = Some(key)
    carried.push((wrapped, parameters))
  }
  guard content_key is Some(key) else {
    raise Malformed("a message needs a content key")
  }
  let loose : Map[String, Json] = Map([])
  for name, value in shared {
    loose[name] = value
  }
  let protected_header : Map[String, Json] = Map([])
  if layout is Layout::Protected {
    place(
      protected_header,
      placed,
      "alg",
      Json::string(recipients[0].alg.name()),
    )
    place_kid(protected_header, placed, recipients[0].header)
  }
  for name, value in signed {
    protected_header[name] = value
  }
  if layout is Layout::Protected {
    for pair in carried {
      for name, value in pair.1 {
        place(protected_header, placed, name, value)
      }
    }
  }
  if layout is Layout::Bare {
    place(loose, placed, "enc", Json::string(enc.name()))
    if compress {
      place(loose, placed, "zip", Json::string("DEF"))
    }
  } else {
    place(protected_header, placed, "enc", Json::string(enc.name()))
    if compress {
      place(protected_header, placed, "zip", Json::string("DEF"))
    }
  }
  // Nothing protected means nothing in front of the additional data: RFC 7516 §5.1 hashes the
  // encoded protected header, and there is none.
  let encoded_head = if layout is Layout::Bare {
    ""
  } else {
    b64(@utf8.encode(@json.dumps(Json::object(protected_header))))
  }
  let authenticated = if aad.length() == 0 {
    @utf8.encode(encoded_head)
  } else {
    @utf8.encode(encoded_head + "." + b64(aad))
  }
  let body = if compress { squeeze(plain) } else { plain.to_owned() }
  let (cipher, tag) = content_seal(enc, key, iv, body[:], authenticated)
  let entries : Array[Json] = []
  let mut at = 0
  for pair in carried {
    let (wrapped, parameters) = pair
    let header : Map[String, Json] = Map([])
    if layout is Layout::Recipient {
      let one = recipients[at]
      place(header, placed, "alg", Json::string(one.alg.name()))
      place_kid(header, placed, one.header)
      for name, value in parameters {
        place(header, placed, name, value)
      }
    }
    at += 1
    let entry : Map[String, Json] = Map([])
    if count_of(header) > 0 {
      entry["header"] = Json::object(header)
    }
    if wrapped.length() > 0 {
      entry["encrypted_key"] = Json::string(b64(wrapped))
    }
    entries.push(Json::object(entry))
  }
  let out : Map[String, Json] = Map([])
  if !(layout is Layout::Bare) {
    out["protected"] = Json::string(encoded_head)
  }
  if count_of(loose) > 0 {
    out["unprotected"] = Json::object(loose)
  }
  out["recipients"] = Json::array(entries)
  if aad.length() > 0 {
    out["aad"] = Json::string(b64(aad))
  }
  out["iv"] = Json::string(b64(iv))
  out["ciphertext"] = Json::string(b64(cipher))
  out["tag"] = Json::string(b64(tag))
  Json::object(out)
}

///|
/// The same message in the flattened serialisation, which holds exactly one recipient.
pub fn flattened(message : Json) -> Json raise Refused {
  let members = match message {
    Object(members) => members
    _ => raise Malformed("a JWE is a JSON object")
  }
  let entries = match members.get("recipients") {
    Some(Array(items)) =>
      if items.length() == 1 {
        items
      } else {
        raise Malformed("the flattened serialisation holds one recipient")
      }
    _ => raise Malformed("a general serialisation has recipients")
  }
  let one = match entries[0] {
    Object(fields) => fields
    _ => raise Malformed("a recipient is an object")
  }
  let out : Map[String, Json] = Map([])
  for name, value in members {
    if name != "recipients" {
      out[name] = value
    }
  }
  for name, value in one {
    out[name] = value
  }
  Json::object(out)
}

///|
/// Open a message in either JSON serialisation.
///
/// `unseal` is what the caller is willing to open with: a token names an algorithm in each
/// recipient's header, and only an algorithm the caller offered is tried, with the key the
/// caller offered for it. The first recipient that opens ends the search, and the index of it
/// comes back so that a caller holding several identities knows which one was his.
pub fn open(
  text : StringView,
  enc~ : Enc,
  unseal~ : Array[Unseal],
  policy~ : Policy = policy,
) -> Opened raise Refused {
  let value = @json.loads(text) catch { _ => raise Malformed("not valid JSON") }
  let members = match value {
    Object(members) => members
    _ => raise Malformed("a JWE JSON serialisation is an object")
  }
  let protected_header = match members.get("protected") {
    Some(String(text)) => object_or_empty(b64_decode(text), "protected header")
    Some(_) => raise Malformed("protected is a string")
    None => Map([])
  }
  let loose = match members.get("unprotected") {
    Some(Object(fields)) => fields
    Some(_) => raise Malformed("unprotected is an object")
    None => Map([])
  }
  if loose.get("zip") is Some(_) {
    raise Malformed("zip has to be in the header that is authenticated")
  }
  let additional = match members.get("aad") {
    Some(String(text)) => b64_decode(text)
    Some(_) => raise Malformed("aad is a string")
    None => b""
  }
  let entries = recipients_of(members)
  let named = match protected_header.get("enc") {
    Some(String(name)) => Enc::of(name[:])
    _ =>
      match loose.get("enc") {
        Some(String(name)) => Enc::of(name[:])
        _ => raise Malformed("the message names no content encryption")
      }
  }
  if named != enc {
    raise Malformed("the message is " + named.name() + ", not " + enc.name())
  }
  let head_text = match members.get("protected") {
    Some(String(text)) => text
    Some(_) => ""
    None => ""
  }
  let aad_text = match members.get("aad") {
    Some(String(text)) => text
    Some(_) => ""
    None => ""
  }
  let authenticated = if aad_text == "" {
    @utf8.encode(head_text)
  } else {
    @utf8.encode(head_text + "." + aad_text)
  }
  let compressed = protected_header.get("zip") is Some(_)
  let iv = field_bytes(members, "iv")
  let cipher = field_bytes(members, "ciphertext")
  let tag = field_bytes(members, "tag")
  let mut at = 0
  for entry in entries {
    let own = match entry.get("header") {
      Some(Object(fields)) => fields
      Some(_) => raise Malformed("a recipient header is an object")
      None => Map([])
    }
    let merged = merge(protected_header, loose, own)
    let alg = named_alg(merged)
    let wrapped = match entry.get("encrypted_key") {
      Some(String(text)) => b64_decode(text)
      Some(_) => raise Malformed("encrypted_key is a string")
      None => b""
    }
    for one in unseal {
      if one.alg == alg {
        match attempt(enc, alg, one.key, wrapped, merged, policy) {
          Some(key) => {
            let plain = content_open(enc, key, iv, cipher, tag, authenticated)
            return {
              plain: if compressed {
                loosen(plain, protected_header)
              } else {
                plain
              },
              aad: additional,
              header: merged,
              index: at,
            }
          }
          None => ()
        }
      }
    }
    at += 1
  }
  raise Key
}

// ------------------------------------------------------------------ the pieces

///|
/// One recipient's key, or nothing when this identity is not the one.
fn attempt(
  enc : Enc,
  alg : Alg,
  identity : Identity,
  wrapped : BytesView,
  header : Map[String, Json],
  policy : Policy,
) -> Bytes? {
  let key = open_recipient(enc, alg, identity, wrapped, header, policy) catch {
    _ => return None
  }
  Some(key)
}

///|
/// The recipients of a general or flattened serialisation, as objects.
fn recipients_of(
  members : Map[String, Json],
) -> Array[Map[String, Json]] raise Refused {
  let out : Array[Map[String, Json]] = []
  match members.get("recipients") {
    Some(Array(items)) =>
      for item in items {
        match item {
          Object(fields) => out.push(fields)
          _ => raise Malformed("a recipient is an object")
        }
      }
    Some(_) => raise Malformed("recipients is an array")
    None => out.push(members)
  }
  out
}

///|
/// The protected header, the shared unprotected one and this recipient's, with the rule that
/// no parameter may be named twice (RFC 7516 §7.2.1).
fn merge(
  protected_header : Map[String, Json],
  shared : Map[String, Json],
  own : Map[String, Json],
) -> Map[String, Json] raise Refused {
  let out : Map[String, Json] = Map([])
  for name, value in protected_header {
    out[name] = value
  }
  for table in [shared, own] {
    for name, value in table {
      if out.get(name) is Some(_) {
        raise Malformed("\{name} is named in two headers of one message")
      }
      out[name] = value
    }
  }
  out
}

///|
fn place(
  into : Map[String, Json],
  placed : Map[String, Json],
  name : String,
  value : Json,
) -> Unit {
  if placed.get(name) is None && into.get(name) is None {
    into[name] = value
  }
}

///|
fn place_kid(
  into : Map[String, Json],
  placed : Map[String, Json],
  from : Map[String, Json],
) -> Unit {
  match from.get("kid") {
    Some(kid) => place(into, placed, "kid", kid)
    None => ()
  }
}

///|
fn count_of(map : Map[String, Json]) -> Int32 {
  let mut n = 0
  for _, _ in map {
    n += 1
  }
  n
}

///|
fn object_or_empty(
  raw : Bytes,
  what : String,
) -> Map[String, Json] raise Refused {
  if raw.length() == 0 {
    return Map([])
  }
  object_of(raw, what)
}

///|
fn field_bytes(
  members : Map[String, Json],
  name : String,
) -> Bytes raise Refused {
  match members.get(name) {
    Some(String(text)) => b64_decode(text)
    Some(_) => raise Malformed(name + " is a string")
    None => raise Malformed("the message has no " + name)
  }
}
