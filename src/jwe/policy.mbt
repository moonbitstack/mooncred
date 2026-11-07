// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// What a message is allowed to ask for: one switch per key-management algorithm that has a
/// reason to be switched.
///
/// Everything RFC 7518 names is supported and accepted without being asked. A recipient that is
/// handed a token with `RSA1_5` in it reads it, because a library that can only read what it
/// would itself have written cannot be put in front of the traffic that already exists.
///
/// The two switches are for the other direction. `RSA1_5`'s decryption is Bleichenbacher's
/// oracle unless every failure is answered identically — this one scans the whole block before
/// it decides and answers `Key` to all of them — but a key that never has to answer the question
/// is stronger than one that answers it carefully, and a deployment that knows its traffic can
/// say so with [`strict`]. `RSA-OAEP` with SHA-1 is the same construction under a hash whose
/// collisions are cheap; it is here for the messages that already exist, not for new ones.
///
/// There is no switch for the other fifteen. They are not a judgement call: AES key wrap, AES-
/// GCM key wrap, RSAES-OAEP with SHA-256, ECDH-ES, PBES2 and `dir` are what a message should
/// use, and a policy that made them optional would be a policy about nothing.
#derive(Eq, Debug)
pub(all) struct Policy {
  /// Whether `RSA1_5` may be used, in either direction.
  rsa1_5 : Bool
  /// Whether `RSA-OAEP` with SHA-1 may be used, in either direction.
  rsa_oaep : Bool
}

///|
pub extend Policy with Eq::{equal, not_equal}

///|
pub extend Policy with Debug::{to_repr}

///|
/// The policy a call uses when the caller does not say otherwise: every algorithm RFC 7518
/// defines.
pub let policy : Policy = { rsa1_5: true, rsa_oaep: true, }

///|
/// The policy that refuses the two algorithms a deployment may not want to answer for. Neither
/// sealing nor opening will use them while this is in force.
pub let strict : Policy = { rsa1_5: false, rsa_oaep: false, }

///|
/// Build a policy by naming the parts that differ from [`policy`].
pub fn Policy::new(
  rsa1_5~ : Bool = policy.rsa1_5,
  rsa_oaep~ : Bool = policy.rsa_oaep,
) -> Policy {
  { rsa1_5, rsa_oaep, }
}

///|
fn Policy::allows(self : Policy, alg : Alg) -> Bool {
  match alg {
    Rsa1_5 => self.rsa1_5
    RsaOaep => self.rsa_oaep
    _ => true
  }
}
