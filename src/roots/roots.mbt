// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The Mozilla CA store as trust anchors: the roots Firefox trusts for TLS servers, as curl
/// extracts them. Each call parses the bundle afresh, so the set returned is the caller's to add
/// to; build it once and keep it.
pub fn mozilla() -> @x509.Roots {
  @x509.Roots::pem(bundle) catch {
    e => abort("the embedded Mozilla bundle does not parse: \{e}")
  }
}
