name = "moonbitstack/mooncred"

version = "0.5.0"

readme = "README.md"

repository = "https://github.com/moonbitstack/mooncred"

license = "Apache-2.0"

keywords = [
  "jwt",
  "jws",
  "jwk",
  "jose",
  "token",
  "credential",
  "oauth2",
  "moonbit",
]

description = "mooncred — credential formats for MoonBit: JSON Web Tokens, JWS, JWK and the JOSE algorithm set, built on mooncrypt's algorithms and moonbase's encodings."

preferred_target = "wasm-gc"

import {
  "moonbitstack/moonbase@0.4.0",
  "moonbitstack/mooncrypt@0.2.2",
  "moonbitstack/moonjson@0.3.0",
}
