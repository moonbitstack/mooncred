// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The examples of RFC 8949 Appendix A, which are what "CBOR" means: a few dozen items, each with
// the octets the specification prints beside it. Reading them back is the only check that the
// head widths are right, and writing them is the only check that the arguments are.

///|
fn from_hex(text : String) -> Bytes {
  @base16.decode(text) catch {
    _ => panic()
  }
}

///|
fn to_hex(octets : BytesView) -> String {
  @base16.encode(octets)
}

///|
/// The empty string when an item and its octets agree in both directions, and what went wrong
/// otherwise. It is not written with `assert_eq` because a helper that calls the assertions has to
/// name the failure type of the test harness, and this reads better as an answer anyway.
fn round_trip(hex : String, value : Value) -> String {
  let written = to_hex(encode(value))
  if written != hex {
    return "\{hex}: written as \{written}"
  }
  let back = decode(from_hex(hex)) catch { _ => return "\{hex}: refused" }
  if back != value {
    return "\{hex}: read back as another value"
  }
  ""
}

///|
/// The integer examples: zero, the boundary at twenty-three, one, ten, twenty-three, twenty-four,
/// a hundred, a thousand, a million, and a negative one at each width.
test "cbor: the integer examples of Appendix A" {
  let cases : Array[(String, Value)] = [
    ("00", Int(0)),
    ("01", Int(1)),
    ("0a", Int(10)),
    ("17", Int(23)),
    ("1818", Int(24)),
    ("1864", Int(100)),
    ("1903e8", Int(1000)),
    ("1a000f4240", Int(1000000)),
    ("1b000000e8d4a51000", Int(1000000000000)),
    ("20", Int(-1)),
    ("29", Int(-10)),
    ("3863", Int(-100)),
    ("3903e7", Int(-1000)),
  ]
  for case in cases {
    assert_eq(round_trip(case.0, case.1), "")
  }
}

///|
/// The strings: empty, short, the one that needs a two-octet length, and a text string with a
/// character that takes two octets to encode.
test "cbor: the string examples of Appendix A" {
  let cases : Array[(String, Value)] = [
    ("40", Bytes(b"")),
    ("4401020304", Bytes(from_hex("01020304"))),
    ("60", Text("")),
    ("6161", Text("a")),
    ("6449455446", Text("IETF")),
    ("62225c", Text("\"\\")),
    ("62c3bc", Text("\u{00FC}")),
    ("63e6b0b4", Text("\u{6C34}")),
  ]
  for case in cases {
    assert_eq(round_trip(case.0, case.1), "")
  }
}

///|
/// The containers: an empty array, three small ones, a map with two pairs, and a map whose value is
/// an array — the shape a COSE header has.
test "cbor: the container examples of Appendix A" {
  let cases : Array[(String, Value)] = [
    ("80", Array([])),
    ("83010203", Array([Int(1), Int(2), Int(3)])),
    (
      "8301820203820405",
      Array([Int(1), Array([Int(2), Int(3)]), Array([Int(4), Int(5)])]),
    ),
    ("a201020304", Map([(Int(1), Int(2)), (Int(3), Int(4))])),
    (
      "a26161016162820203",
      Map([(Text("a"), Int(1)), (Text("b"), Array([Int(2), Int(3)]))]),
    ),
    ("826161a161626163", Array([Text("a"), Map([(Text("b"), Text("c"))])])),
    (
      "a56161614161626142616361436164614461656145",
      Map([
        (Text("a"), Text("A")),
        (Text("b"), Text("B")),
        (Text("c"), Text("C")),
        (Text("d"), Text("D")),
        (Text("e"), Text("E")),
      ]),
    ),
  ]
  for case in cases {
    assert_eq(round_trip(case.0, case.1), "")
  }
}

///|
/// The simple values and tags: false, true, null, undefined, a simple value with no name, a tag,
/// and the two registered tags with a byte string inside.
test "cbor: the simple values and tags of Appendix A" {
  let cases : Array[(String, Value)] = [
    ("f4", Bool(false)),
    ("f5", Bool(true)),
    ("f6", Null),
    ("f7", Undefined),
    ("f0", Simple(16)),
    (
      "c074323031332d30332d32315432303a30343a30305a",
      Tag(0UL, Text("2013-03-21T20:04:00Z")),
    ),
    ("d74401020304", Tag(23UL, Bytes(from_hex("01020304")))),
    ("d818456449455446", Tag(24UL, Bytes(from_hex("6449455446")))),
    (
      "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
      Tag(32UL, Text("http://www.example.com")),
    ),
  ]
  for case in cases {
    assert_eq(round_trip(case.0, case.1), "")
  }
}

///|
/// A decoded item that is not followed by the end of the input, or is cut short, is refused rather
/// than returned half read.
test "cbor: a truncated or trailed item is refused" {
  for hex in ["", "18", "1b00", "44010203", "830102", "a2010203", "c0", "0000"] {
    let refused = try {
      decode(from_hex(hex)) |> ignore
      false
    } catch {
      Malformed(_) => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
/// The two encodings this decoder declines, and says it declines rather than mistaking them for
/// something it understands: an indefinite length, and a floating-point item.
test "cbor: indefinite lengths and floats are unsupported, not malformed" {
  for hex in ["9f01ff", "5f4101ff", "fb3ff0000000000000"] {
    let refused = try {
      decode(from_hex(hex)) |> ignore
      false
    } catch {
      Unsupported(_) => true
      _ => false
    }
    assert_true(refused)
  }
}

///|
/// Nesting is bounded, so a document that describes too many arrays inside one another is refused
/// instead of taking the stack with it.
test "cbor: nesting is bounded" {
  let octets = Buffer()
  for _ in 0..<80 {
    octets.write_byte(0x81)
  }
  octets.write_byte(0x00)
  let refused = try {
    decode(octets.to_bytes()[:]) |> ignore
    false
  } catch {
    Malformed(_) => true
    _ => false
  }
  assert_true(refused)
}

///|
/// Reading a value out of a map by its key, which is how a COSE header is read: the first pair with
/// the key wins, and a value that is not a map holds nothing.
test "cbor: a map can be read by key" {
  let map = Map([
    (Int(1), Int(-7)),
    (Int(4), Bytes(from_hex("0102"))),
    (Int(1), Int(0)),
  ])
  assert_eq(map.get(Int(1)), Some(Int(-7)))
  assert_eq(map.get(Int(4)), Some(Bytes(from_hex("0102"))))
  assert_eq(map.get(Int(9)), None)
  assert_eq(Text("x").get(Int(1)), None)
  assert_eq(Int(5).int(), Some(5L))
  assert_eq(Text("x").int(), None)
  assert_eq(Bytes(from_hex("00")).bytes(), Some(from_hex("00")))
  assert_eq(Text("x").bytes(), None)
}
