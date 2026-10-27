///|
/// 2026-01-01T00:00:00Z: inside every fixture's window but the two made to miss it.
let now : Int64 = 1767225600

///|
fn der(text : String) -> Bytes raise {
  @x509.pem(text)
}

///|
fn ders(texts : Array[String]) -> Array[Bytes] raise {
  texts.map(der)
}

///|
fn roots(texts : Array[String]) -> @x509.Roots raise {
  @x509.Roots::new(certs=ders(texts)[:])
}

///|
/// The subjects' commonNames along a returned path.
fn names(path : Array[@x509.Cert]) -> Array[String] {
  path.map(c => c.subject.cn().unwrap_or("?"))
}

///|
/// What `verify` refuses `chain` with.
fn refused(
  chain : Array[Bytes],
  roots : @x509.Roots,
  at~ : Int64 = now,
  host? : String,
  policy? : @x509.Policy,
) -> @x509.Refused raise {
  try
    @x509.verify(
      chain[:],
      roots,
      now=at,
      host?,
      policy=policy.unwrap_or(@x509.policy),
    )
  catch {
    e => e
  } noraise {
    p => fail("expected a refusal, got a path of \{p.length()}")
  }
}

///|
test "verify: RSA root, RSA intermediate, P-256 leaf signed with SHA-384" {
  let path = @x509.verify(
    ders([leaf, rsa_inter])[:],
    roots([rsa_root]),
    now~,
    host="a.example",
  )
  assert_eq(names(path), ["leaf", "rsa inter", "rsa root"])
}

///|
test "verify: the intermediates may arrive in any order, with extras" {
  let path = @x509.verify(
    ders([leaf, ed_root, rsa_inter, p384_root])[:],
    roots([rsa_root]),
    now~,
  )
  assert_eq(names(path), ["leaf", "rsa inter", "rsa root"])
}

///|
test "verify: ECDSA P-384, Ed25519 and RSASSA-PSS issuers" {
  let p = @x509.verify(
    ders([p384_leaf])[:],
    roots([p384_root]),
    now~,
    host="b.example",
  )
  assert_eq(names(p), ["p384 leaf", "p384 root"])
  let e = @x509.verify(
    ders([ed_leaf])[:],
    roots([ed_root]),
    now~,
    host="c.example",
  )
  assert_eq(names(e), ["ed leaf", "ed root"])
  let s = @x509.verify(
    ders([pss_leaf])[:],
    roots([pss_root]),
    now~,
    host="d.example",
  )
  assert_eq(names(s), ["pss leaf", "pss root"])
}

///|
test "verify: hosts match subjectAltName names and addresses, wildcards one label deep" {
  let chain = ders([leaf, rsa_inter])
  let r = roots([rsa_root])
  for
    h in [
      "a.example", "A.Example", "a.example.", "x.w.example", "127.0.0.1", "::1",
      "[::1]", "0:0::1",
    ] {
    @x509.verify(chain[:], r, now~, host=h) |> ignore
  }
  for
    h in [
      "b.example", "w.example", "y.x.w.example", "127.0.0.2", "127.000.0.1", "leaf",
    ] {
    assert_eq(refused(chain, r, host=h), Host(h))
  }
}

///|
test "verify: validity is checked on the leaf and the intermediates, not the anchor" {
  let r = roots([rsa_root])
  assert_eq(refused(ders([expired, rsa_inter]), r), Expired(at=0))
  assert_eq(refused(ders([early_leaf, early_inter]), r), Premature(at=1))
  // 2041, after the root's own notAfter too: the leaf is the one refused
  assert_eq(refused(ders([leaf, rsa_inter]), r, at=2240611200), Expired(at=0))
}

///|
test "verify: an issuer must be a CA with keyCertSign, within its pathLenConstraint" {
  let r = roots([rsa_root])
  assert_eq(refused(ders([noca_leaf, noca_inter]), r), Authority(at=1))
  assert_eq(refused(ders([nosign_leaf, nosign_inter]), r), Authority(at=1))
  assert_eq(
    refused(ders([pl0_leaf, below_inter, pl0_inter]), r),
    Authority(at=2),
  )
}

///|
test "verify: a CA is not a leaf" {
  assert_eq(refused(ders([rsa_inter]), roots([rsa_root])), Authority(at=0))
}

///|
test "verify: the leaf must allow the purpose asked for" {
  let chain = ders([client, rsa_inter])
  let r = roots([rsa_root])
  assert_eq(refused(chain, r), Purpose(at=0))
  let p = @x509.verify(
    chain[:],
    r,
    now~,
    policy=@x509.Policy::new(usage=Client),
  )
  assert_eq(names(p), ["client", "rsa inter", "rsa root"])
  @x509.verify(chain[:], r, now~, policy=@x509.Policy::new(usage=Any)) |> ignore
}

///|
test "verify: an unknown critical extension refuses the chain" {
  assert_eq(
    refused(ders([critical, rsa_inter]), roots([rsa_root])),
    Critical(at=0, oid="1.2.3.4"),
  )
}

///|
test "verify: name constraints bind DNS names and addresses below the CA" {
  let r = roots([rsa_root])
  @x509.verify(ders([nc_ok, nc_inter])[:], r, now~) |> ignore
  assert_eq(
    refused(ders([nc_dns, nc_inter]), r),
    Constraint(at=0, name="x.other.example"),
  )
  assert_eq(
    refused(ders([nc_ip, nc_inter]), r),
    Constraint(at=0, name="0a010203"),
  )
  assert_eq(
    refused(ders([nc_root_leaf]), roots([nc_root])),
    Constraint(at=0, name="x.other.example"),
  )
}

///|
test "verify: no issuer, a bad signature, a malformed chain" {
  let r = roots([rsa_root])
  assert_eq(refused(ders([leaf]), r), Issuer)
  assert_eq(refused(ders([leaf]), roots([p384_root])), Issuer)
  let bytes = der(leaf).to_array()
  bytes[bytes.length() - 1] = bytes[bytes.length() - 1] ^ b'\x01'
  assert_eq(
    refused([Bytes::from_array(bytes), der(rsa_inter)], r),
    Signature(at=0),
  )
  assert_eq(refused([], r), Malformed(at=0, "empty chain"))
  assert_true(refused([b"\x30\x00"], r) is Malformed(at=0, _))
}

///|
test "verify: depth and the signature budget bound the search" {
  let r = roots([rsa_root])
  assert_eq(
    refused(ders([leaf, rsa_inter]), r, policy=@x509.Policy::new(depth=0)),
    Depth(limit=0),
  )
  let decoyed = ders([
    decoyed_leaf, decoy0, decoy1, decoy2, decoy3, decoy4, decoyed_inter,
  ])
  assert_eq(names(@x509.verify(decoyed[:], r, now~)), [
    "decoyed leaf", "decoyed", "rsa root",
  ])
  assert_eq(
    refused(decoyed, r, policy=@x509.Policy::new(budget=3)),
    Budget(limit=3),
  )
}

///|
test "verify: the key identifier puts the likely issuer first" {
  let p = @x509.verify(
    ders([leaf, decoy0, decoy1, rsa_inter])[:],
    roots([rsa_root]),
    now~,
    policy=@x509.Policy::new(budget=2),
  )
  assert_eq(names(p), ["leaf", "rsa inter", "rsa root"])
}

///|
test "roots: from a PEM bundle, duplicates kept once" {
  let bundle = "# a bundle\n" +
    rsa_root +
    "\nprose between\n" +
    p384_root +
    "\n" +
    rsa_root
  let r = @x509.Roots::pem(bundle)
  assert_eq(r.length(), 2)
  assert_eq(r.iter().map(c => c.subject.cn().unwrap_or("?")).collect(), [
    "rsa root", "p384 root",
  ])
  assert_eq(@x509.pems(bundle).length(), 3)
}

///|
test "policy: the three ways of writing one agree" {
  assert_eq(@x509.Policy::new(), @x509.policy)
  assert_eq(@x509.Policy::new(depth=3), { ..@x509.policy, depth: 3, })
  assert_eq(@x509.policy, {
    usage: Server,
    depth: 6,
    budget: 100,
    comparisons: 250_000,
    bits: 2048,
  })
}

///|
test "verify: a wildcard falls under an exclusion it could expand into (CVE-2025-61727)" {
  assert_eq(
    refused(ders([wild_leaf, wild_inter]), roots([rsa_root])),
    Constraint(at=0, name="*.example.com"),
  )
}

///|
test "verify: a URI constraint without a dot names one host" {
  let r = roots([rsa_root])
  @x509.verify(ders([uri_ok, uri_inter])[:], r, now~) |> ignore
  assert_eq(
    refused(ders([uri_sub, uri_inter]), r),
    Constraint(at=0, name="https://sub.example.com/x"),
  )
}

///|
test "verify: an RSA key below the policy's bits signs nothing" {
  let chain = ders([weak_leaf])
  let r = roots([weak_root])
  assert_eq(refused(chain, r), Weak(at=0))
  @x509.verify(chain[:], r, now~, policy=@x509.Policy::new(bits=1024)) |> ignore
}

///|
test "verify: name-constraint comparisons are bounded" {
  let chain = ders([nc_ok, nc_inter])
  let r = roots([rsa_root])
  assert_eq(
    refused(chain, r, policy=@x509.Policy::new(comparisons=0)),
    Comparisons(limit=0),
  )
}

///|
test "refused: reads as a sentence" {
  assert_eq(@x509.Expired(at=1).to_string(), "certificate 1 has expired")
  assert_eq(
    @x509.Host("a.example").to_string(),
    "the certificate does not name a.example",
  )
}
