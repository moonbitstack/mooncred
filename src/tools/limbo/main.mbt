// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The C2SP x509-limbo suite, run against `x509.verify`.
//
// The suite is read from standard input, so CI feeds it straight from the file it
// downloaded and no path has to survive a command line. Each case is judged the way
// limbo asks: a leaf, the intermediates the peer sent, a set of anchors, a time, and
// a name to match when the case names one. A case whose fields this validator has no
// way to act on is reported as unsupported rather than counted as agreement.
//
//     moon run src/tools/limbo --target native < limbo.json
//
// The exit status is 0 when every case this validator ran ended the way limbo says it
// should, and 1 otherwise.

///|
extern "C" fn stdin_bytes() -> Bytes = "mooncred_limbo_stdin"

///|
fn main {
  let suite = read_suite()
  let cases = cases_of(suite)
  let mut agreed = 0
  let mut disagreed = 0
  let mut unsupported = 0
  for item in cases {
    match Case::read(item) {
      None => println("MALFORMED a case without an id")
      Some(c) =>
        match judge(c) {
          Agreed => agreed = agreed + 1
          Disagreed(why) => {
            disagreed = disagreed + 1
            println("DISAGREE \{c.id}: " + why)
          }
          Unsupported(why) => {
            unsupported = unsupported + 1
            println("UNSUPPORTED \{c.id}: " + why)
          }
        }
    }
  }
  println(
    "limbo: \{cases.length()} cases, \{agreed} agreed, \{disagreed} disagreed, \{unsupported} unsupported",
  )
  if disagreed > 0 {
    @env.exit(1)
  }
}

///|
fn read_suite() -> Json {
  let bytes = stdin_bytes()
  guard bytes.length() > 0 else {
    println("limbo: nothing on standard input")
    @env.exit(2)
  }
  let text = @utf8.decode(bytes) catch {
    _ => {
      println("limbo: the suite is not UTF-8")
      @env.exit(2)
    }
  }
  @moonjson.loads(text, @moonjson.strict) catch {
    e => {
      println("limbo: the suite is not JSON: " + e.message())
      @env.exit(2)
    }
  }
}

///|
fn cases_of(suite : Json) -> Array[Json] {
  match suite {
    Object(fields) =>
      match fields.get("testcases") {
        Some(Array(items)) => items
        _ => []
      }
    _ => []
  }
}
