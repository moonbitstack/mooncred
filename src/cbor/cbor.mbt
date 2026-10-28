// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Concise Binary Object Representation (RFC 8949): the data model COSE and CWT are written in.
//
// This is the subset those two specifications use — integers, byte and text strings, arrays,
// maps, tags and the three simple values — encoded with definite lengths only. Indefinite
// lengths are refused rather than assembled: they exist for a streaming writer, they make a
// decoder's bounds harder to argue about, and RFC 9052 §1.1 lets an implementation decline them.

///|
/// Why some octets are not a CBOR item.
pub(all) suberror Refused {
  Malformed(String)
  Unsupported(String)
} derive(Eq, Debug)

///|
/// A CBOR item.
///
/// `Int` covers both major types 0 and 1, so an integer reads as the number it is rather than as
/// a sign and a magnitude the caller has to combine. That costs the top half of the unsigned
/// range, which is refused on the way in: nothing in a credential or a token is a 2^63-byte count.
pub(all) enum Value {
  Int(Int64)
  Bytes(Bytes)
  Text(String)
  Array(Array[Value])
  /// Keys in the order they were written: a map is a sequence of pairs, not a lookup, and
  /// rewriting it would change the octets a signature covers.
  Map(Array[(Value, Value)])
  Tag(UInt64, Value)
  Bool(Bool)
  Null
  Undefined
  /// A simple value that is not one of the three above, kept so a decoder can hand back what it
  /// was given even where it has no opinion about it.
  Simple(Byte)
} derive(Eq, Debug)

///|
/// The octets of an item: definite lengths, and the shortest head that holds the argument.
pub fn encode(value : Value) -> Bytes {
  let out = Buffer()
  write(out, value)
  out.to_bytes()
}

///|
fn write(out : Buffer, value : Value) -> Unit {
  match value {
    Int(n) =>
      if n >= 0 {
        head(out, 0, n.reinterpret_as_uint64())
      } else {
        // Major type 1 holds -1 - n, so the argument is -(n + 1) in unsigned arithmetic:
        // written this way, the most negative integer does not overflow on the way in.
        head(out, 1, (-(n + 1)).reinterpret_as_uint64())
      }
    Bytes(b) => {
      head(out, 2, b.length().to_uint64())
      out.write_bytes(b[:])
    }
    Text(s) => {
      let bytes = @utf8.encode(s)
      head(out, 3, bytes.length().to_uint64())
      out.write_bytes(bytes[:])
    }
    Array(items) => {
      head(out, 4, items.length().to_uint64())
      for item in items {
        write(out, item)
      }
    }
    Map(pairs) => {
      head(out, 5, pairs.length().to_uint64())
      for pair in pairs {
        write(out, pair.0)
        write(out, pair.1)
      }
    }
    Tag(number, inner) => {
      head(out, 6, number)
      write(out, inner)
    }
    Bool(true) => out.write_byte(0xF5)
    Bool(false) => out.write_byte(0xF4)
    Null => out.write_byte(0xF6)
    Undefined => out.write_byte(0xF7)
    Simple(n) =>
      if n < 24 {
        out.write_byte(0xE0 | n)
      } else {
        out.write_byte(0xF8)
        out.write_byte(n)
      }
  }
}

///|
/// An initial byte and its argument, in the shortest form that holds it.
fn head(out : Buffer, major : Int32, argument : UInt64) -> Unit {
  let lead = major << 5
  if argument < 24UL {
    out.write_byte((lead | argument.to_int()).to_byte())
  } else if argument < 256UL {
    out.write_byte((lead | 24).to_byte())
    out.write_byte(argument.to_byte())
  } else if argument < 65536UL {
    out.write_byte((lead | 25).to_byte())
    out.write_byte((argument >> 8).to_byte())
    out.write_byte(argument.to_byte())
  } else if argument < 4294967296UL {
    out.write_byte((lead | 26).to_byte())
    for i in [3, 2, 1, 0] {
      out.write_byte((argument >> (i * 8)).to_byte())
    }
  } else {
    out.write_byte((lead | 27).to_byte())
    for i in [7, 6, 5, 4, 3, 2, 1, 0] {
      out.write_byte((argument >> (i * 8)).to_byte())
    }
  }
}

///|
/// Read one item, and insist that nothing follows it.
pub fn decode(octets : BytesView) -> Value raise Refused {
  let (value, used) = item(octets, 0, 0)
  if used != octets.length() {
    raise Malformed(
      "the item ends at \{used} of \{octets.length()} octets, which leaves a tail",
    )
  }
  value
}

///|
/// How deep nesting may go before it is refused. A decoder that follows a self-referential
/// document down its own stack crashes; one that counts does not.
let deepest : Int32 = 64

///|
/// One item, and how many octets it took.
fn item(
  octets : BytesView,
  at : Int32,
  depth : Int32,
) -> (Value, Int32) raise Refused {
  if depth > deepest {
    raise Malformed("an item nested more than \{deepest} deep")
  }
  if at >= octets.length() {
    raise Malformed("an item that runs past the end")
  }
  let lead = octets[at].to_int()
  let major = lead >> 5
  let small = lead & 0x1F
  if major == 7 {
    return simple(octets, at, small)
  }
  let (argument, after) = argument(octets, at + 1, small)
  match major {
    0 => {
      if argument > 0x7FFFFFFFFFFFFFFFUL {
        raise Unsupported("an integer past the signed range")
      }
      (Int(argument.reinterpret_as_int64()), after)
    }
    1 => (Int(-1L - argument.reinterpret_as_int64()), after)
    2 => (Bytes(take(octets, after, argument)), after + argument.to_int())
    3 => {
      let slice = take(octets, after, argument)
      let text = @utf8.decode(slice) catch {
        _ => raise Malformed("a text string that is not UTF-8")
      }
      (Text(text), after + argument.to_int())
    }
    4 => {
      let items : Array[Value] = []
      let mut cursor = after
      for _ in 0..<argument.to_int() {
        let (inner, next) = item(octets, cursor, depth + 1)
        items.push(inner)
        cursor = next
      }
      (Array(items), cursor)
    }
    5 => {
      let pairs : Array[(Value, Value)] = []
      let mut cursor = after
      for _ in 0..<argument.to_int() {
        let (key, after_key) = item(octets, cursor, depth + 1)
        let (value, after_value) = item(octets, after_key, depth + 1)
        pairs.push((key, value))
        cursor = after_value
      }
      (Map(pairs), cursor)
    }
    _ => {
      let (inner, next) = item(octets, after, depth + 1)
      (Tag(argument, inner), next)
    }
  }
}

///|
/// Major type 7: the three booleans, the two empties, and whatever else a writer put there.
fn simple(
  octets : BytesView,
  at : Int32,
  small : Int32,
) -> (Value, Int32) raise Refused {
  if small < 20 {
    // The unassigned simple values: nothing in COSE names them, so they travel as themselves.
    return (Simple(small.to_byte()), at + 1)
  }
  match small {
    20 => (Bool(false), at + 1)
    21 => (Bool(true), at + 1)
    22 => (Null, at + 1)
    23 => (Undefined, at + 1)
    24 => {
      if at + 1 >= octets.length() {
        raise Malformed("a simple value that runs past the end")
      }
      (Simple(octets[at + 1]), at + 2)
    }
    25 | 26 | 27 =>
      // Half, single and double precision share the encoding but not the meaning, and reading
      // one back as a number the caller can use means picking a representation for it. Neither
      // COSE nor CWT writes them, so this decoder says so rather than guessing.
      raise Unsupported("a floating-point item")
    _ => raise Malformed("a reserved simple value")
  }
}

///|
/// The argument of an initial byte, and where it ended.
fn argument(
  octets : BytesView,
  at : Int32,
  small : Int32,
) -> (UInt64, Int32) raise Refused {
  if small < 24 {
    return (small.to_uint64(), at)
  }
  let width = match small {
    24 => 1
    25 => 2
    26 => 4
    27 => 8
    31 => raise Unsupported("an indefinite length")
    _ => raise Malformed("a reserved argument width")
  }
  if at + width > octets.length() {
    raise Malformed("an argument that runs past the end")
  }
  let mut value = 0UL
  for i in 0..<width {
    value = (value << 8) | octets[at + i].to_uint64()
  }
  (value, at + width)
}

///|
/// `count` octets from `at`, or a refusal: a length is written by whoever wrote the document, so
/// it is checked before it is used to cut.
fn take(octets : BytesView, at : Int32, count : UInt64) -> Bytes raise Refused {
  if count > octets.length().to_uint64() ||
    at + count.to_int() > octets.length() {
    raise Malformed("a length that runs past the end")
  }
  octets[at:at + count.to_int()].to_owned()
}

///|
/// Look a key up in a map, which is a sequence of pairs rather than a lookup: the first pair with
/// that key wins, as it would in an object read in order.
pub fn Value::get(self : Value, key : Value) -> Value? {
  guard self is Map(pairs) else { return None }
  for pair in pairs {
    if pair.0 == key {
      return Some(pair.1)
    }
  }
  None
}

///|
/// The integer a key holds, if it holds one.
pub fn Value::int(self : Value) -> Int64? {
  guard self is Int(n) else { return None }
  Some(n)
}

///|
/// The octets a value holds, if it holds any.
pub fn Value::bytes(self : Value) -> Bytes? {
  guard self is Bytes(b) else { return None }
  Some(b)
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}

///|
pub extend Value with Eq::{equal, not_equal}

///|
pub extend Value with Debug::{to_repr}
