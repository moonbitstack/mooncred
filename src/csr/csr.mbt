// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A certification request (RFC 2986) is what a client sends when it has a key and wants a
// certificate for it: the subject it claims, the public key, the extensions it would like, and a
// signature over all of that under the private key. The signature is the whole point — it proves
// the requester holds the key it is asking to have certified — and it is also all a request
// proves: a request is not a credential, and nothing in it is trustworthy until a CA signs.

///|
/// A parsed certification request. `tbs` is the exact `CertificationRequestInfo` the signature
/// covers, kept as a view into the input for the same reason a certificate keeps its own: a
/// signature is checked over the octets that arrived, never over a re-encoding of them.
pub(all) struct Request {
  raw : BytesView
  tbs : BytesView
  subject : @x509.Name
  spki : @x509.Spki
  /// The extensions the `extensionRequest` attribute carries, empty when it has none.
  exts : @x509.Exts
  alg : String
  params : Bytes?
  sig : @asn1.Bits
}

///|
/// The `extensionRequest` attribute (RFC 2985 §5.4): one `Extensions` SEQUENCE inside a SET.
let oid_extension_request : String = "1.2.840.113549.1.9.14"

///|
/// Read a DER certification request.
///
/// Anything that is not exactly one well-formed request is `Malformed`: a version other than v1,
/// a field past the attributes, an attribute that repeats, or an `extensionRequest` that does not
/// carry exactly one `Extensions`. The signature is not checked here — `verified` does that, and
/// keeping the two apart is what lets a caller read a request it cannot yet verify.
pub fn parse(der : BytesView) -> Request raise @asn1.Refused {
  let top = @asn1.only(der)
  if top.tag != 0x30 {
    raise @asn1.Malformed("CertificationRequest is not a SEQUENCE")
  }
  let items = top.items()
  if items.length() != 3 {
    raise @asn1.Malformed(
      "CertificationRequest is not an info, an algorithm and a signature",
    )
  }
  if items[0].tag != 0x30 {
    raise @asn1.Malformed("CertificationRequestInfo is not a SEQUENCE")
  }
  let f = items[0].items()
  if f.length() < 3 {
    raise @asn1.Malformed("CertificationRequestInfo is missing fields")
  }
  if f[0].int() != 0 {
    raise @asn1.Malformed("certification request version is not v1")
  }
  let subject = @x509.name(f[1].raw)
  let spki = @x509.Spki::read(f[2].raw)
  let mut exts = @x509.Exts::empty()
  if f.length() > 4 {
    raise @asn1.Malformed("unexpected field in CertificationRequestInfo")
  }
  if f.length() == 4 {
    exts = read_attributes(f[3])
  }
  let (alg, params) = @x509.algorithm(items[1].raw)
  {
    raw: top.raw,
    tbs: items[0].raw,
    subject,
    spki,
    exts,
    alg,
    params,
    sig: items[2].bits(),
  }
}

///|
/// The extensions inside the request's `attributes [0]`, from the `extensionRequest` attribute and
/// no other: an attribute this package does not know is passed over rather than refused, because
/// RFC 2986 lets a request carry attributes a reader has never heard of and the CA is the one that
/// decides what to do with them.
fn read_attributes(t : @asn1.Tlv) -> @x509.Exts raise @asn1.Refused {
  if t.tag != 0xa0 {
    raise @asn1.Malformed("attributes are not [0]-tagged")
  }
  let mut exts = @x509.Exts::empty()
  let seen : Array[String] = []
  for a in t.items() {
    if a.tag != 0x30 {
      raise @asn1.Malformed("attribute is not a SEQUENCE")
    }
    let parts = a.items()
    if parts.length() != 2 {
      raise @asn1.Malformed("attribute is not a type and its values")
    }
    if parts[1].tag != 0x31 {
      raise @asn1.Malformed("attribute values are not a SET")
    }
    let oid = parts[0].oid()
    if seen.contains(oid) {
      raise @asn1.Malformed("attribute " + oid + " appears twice")
    }
    seen.push(oid)
    if oid == oid_extension_request {
      let values = parts[1].items()
      if values.length() != 1 {
        raise @asn1.Malformed(
          "extensionRequest must carry exactly one Extensions",
        )
      }
      exts = @x509.exts(values[0].raw)
    }
  }
  exts
}

///|
/// Read the first certification request in a PEM file. `openssl req` writes the label
/// `CERTIFICATE REQUEST`; the older `NEW CERTIFICATE REQUEST` is read too, because files with it
/// are still in the wild.
pub fn Request::pem(text : String) -> Request raise @asn1.Refused {
  for label in ["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"] {
    if @x509.pems(text, label~) is [der, ..] {
      return parse(der[:])
    }
  }
  raise @asn1.Malformed("no certification request in the PEM text")
}

///|
/// The DER this request arrived as.
pub fn Request::der(self : Request) -> BytesView {
  self.raw
}

///|
/// The PEM envelope around this request, in the label `openssl req` writes.
pub fn Request::to_pem(self : Request) -> String {
  @x509.pem_wrap(self.raw, label="CERTIFICATE REQUEST")
}

///|
/// Whether the request's signature verifies under the public key it carries. A request is always
/// self-signed — that is what separates it from a certificate — so the key to check against is
/// the one inside it, and an algorithm this package does not implement raises `Unsupported`
/// rather than returning false.
pub fn Request::verified(self : Request) -> Bool raise @asn1.Refused {
  @x509.signature_ok(
    self.tbs,
    alg=self.alg,
    params=self.params,
    sig=self.sig,
    key=self.spki,
  )
}

///|
/// Whether the request asks for the certificate of this key: the key inside the request and this
/// one are the same. A CA compares before it issues, so a request and the key it was made from
/// cannot be swapped for another pair.
pub fn Request::asks_for(self : Request, key : Key) -> Bool {
  let inside = @x509.Spki::key(self.spki) catch { _ => return false }
  inside == key
}

///|
/// The signature scheme each kind of key is written with here: ECDSA and RSA with SHA-256, and
/// Ed25519 as itself. The request names the scheme in its AlgorithmIdentifier and the signature
/// is made with the same one, which is the pairing a verifier relies on.
fn scheme_of(key : @x509.PrivateKey) -> Bytes {
  match key {
    Rsa(_) =>
      @asn1.sequence([@asn1.oid([1, 2, 840, 113549, 1, 1, 11]), @asn1.null()])
    Ec(_) => @asn1.sequence([@asn1.oid([1, 2, 840, 10045, 4, 3, 2])])
    Ed25519(_) => @asn1.sequence([@asn1.oid([1, 3, 101, 112])])
  }
}

///|
/// Sign `tbs` under `key`, in the scheme `scheme_of` names for it. An EC key is re-created with
/// SHA-256 rather than signed with whatever digest it was built with, so the digest the
/// AlgorithmIdentifier advertises is the digest the signature used.
fn sign(key : @x509.PrivateKey, tbs : Bytes) -> Bytes raise @asn1.Refused {
  match key {
    Rsa(k) => k.with_scheme(digest=@rsa.Sha256, scheme=@rsa.Pkcs1).sign(tbs[:])
    Ec(k) => {
      let signer = @ecdsa.PrivateKey::with_hash(
        k.bytes(),
        () => (@sha2.Hasher::new(kind=Sha256) : &@spec.Hash),
        curve=k.curve(),
      ) catch {
        _ => raise @asn1.Malformed("EC key cannot be re-read for signing")
      }
      let raw = signer.sign(tbs[:])
      let size = k.curve().size()
      if raw.length() != size * 2 {
        raise @asn1.Malformed("ECDSA signature is not two scalars")
      }
      // RFC 3279 §2.2.3: the signature is the DER of SEQUENCE { r, s }, not the concatenation
      // every other ECDSA API hands back.
      @asn1.sequence([
        @asn1.integer(raw[0:size].to_owned()),
        @asn1.integer(raw[size:size * 2].to_owned()),
      ])
    }
    Ed25519(k) => k.sign(tbs[:])
  }
}

///|
/// Write a certification request for a key in hand (RFC 2986 §4).
///
/// `subject` is the DER of a `Name` — `@x509.common_name` for the usual case — and `exts` the
/// extensions to ask for, which travel in an `extensionRequest` attribute. The request is signed
/// by `key`, so the CA that reads it can tell the requester holds the private half.
pub fn self_signed(
  key : @x509.PrivateKey,
  subject~ : Bytes,
  exts~ : @x509.Exts? = None,
) -> Bytes raise @asn1.Refused {
  let attributes = match exts {
    None => @asn1.tlv(0xa0, b"")
    Some(e) => {
      let body = @x509.Exts::encode(e)
      @asn1.tlv(
        0xa0,
        @asn1.sequence([
          @asn1.oid([1, 2, 840, 113549, 1, 9, 14]),
          @asn1.set_of([body]),
        ]),
      )
    }
  }
  let tbs = @asn1.sequence([
    @asn1.integer(b"\x00"),
    subject,
    @x509.Spki::encode(key.public()),
    attributes,
  ])
  let sig = sign(key, tbs)
  @asn1.sequence([tbs, scheme_of(key), @asn1.bit_string(sig)])
}

///|
/// The same request inside the PEM envelope `openssl req` writes.
pub fn self_signed_pem(
  key : @x509.PrivateKey,
  subject~ : Bytes,
  exts~ : @x509.Exts? = None,
) -> String raise @asn1.Refused {
  let der = self_signed(key, subject~, exts~)
  @x509.pem_wrap(der[:], label="CERTIFICATE REQUEST")
}

///|
pub using @x509 {type Key}
