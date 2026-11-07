// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What a message is allowed to ask for.
///
/// `RSA1_5` and `RSA-OAEP` with SHA-1 are in RFC 7516 and are refused here by default. The
/// first has a decryption oracle written into its own history — Bleichenbacher's attack, and
/// the padding oracle that came back with every implementation that answered too quickly —
/// and the second is the same construction under a hash that is no longer a barrier. Both are
/// still in the field, so both can be turned on, in one place, deliberately.
#derive(Eq, Debug)
pub(all) struct Policy {
  /// Whether `RSA1_5` and `RSA-OAEP` (SHA-1) are accepted.
  legacy : Bool
}

///|
pub extend Policy with Eq::{equal, not_equal}

///|
pub extend Policy with Debug::{to_repr}

///|
/// The policy a call uses when the caller does not say otherwise.
pub let policy : Policy = { legacy: false, }

///|
/// The policy that accepts the two algorithms this library will not take by default.
pub let legacy : Policy = { legacy: true, }

///|
/// Build a policy by naming the parts that differ from the default.
pub fn Policy::new(legacy~ : Bool = policy.legacy) -> Policy {
  { legacy, }
}

///|
fn Policy::allows(self : Policy, alg : Alg) -> Bool {
  match alg {
    Rsa1_5 | RsaOaep => self.legacy
    _ => true
  }
}
