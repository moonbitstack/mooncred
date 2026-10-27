///|
test "roots: every certificate in the bundle is read" {
  assert_eq(mozilla().length(), count)
  assert_true(count > 100)
}

///|
test "roots: each anchor's fingerprint is the one curl lists beside it" {
  let listed = bundle
    .split("\n")
    .filter_map(l => l.strip_prefix("# Fingerprint (SHA-256): "))
    .map(f => f.to_owned().replace_all(old=":", new=""))
    .collect()
  let got = mozilla()
    .iter()
    .map(c => @base16.encode(@sha2.hash(c.raw), kind=Upper))
    .collect()
  assert_eq(got, listed)
}
