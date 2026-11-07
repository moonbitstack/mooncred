// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The other half of the interoperability vectors: go-jose seals a set of messages, and opens the
// ones `src/examples/interop` wrote with this library. `scripts/gen_jose_vectors.py` runs it and
// records both halves; the tests replay them. Nothing here is random in a way that matters — a
// token go-jose seals is opened by this library, and a token this library seals is opened by
// go-jose, and neither compares bytes with the other's.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"

	jose "github.com/go-jose/go-jose/v4"
)

var hmackey = mustHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
var kek128 = mustHex("404142434445464748494a4b4c4d4e4f")
var kek256 = mustHex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
var password = []byte("correct horse battery staple")
// Small scalars on P-256: the point of the curve itself at one, and three times it at three.
func scalarKey(d int64) *ecdsa.PrivateKey {
	params := elliptic.P256().Params()
	x, y := elliptic.P256().ScalarBaseMult(big.NewInt(d).Bytes())
	_ = params
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         big.NewInt(d),
	}
}

var ecKey = scalarKey(1)
var peerKey = scalarKey(3)

func mustHex(text string) []byte {
	out, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return out
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

type sealed struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Token     string `json:"token"`
	Plaintext string `json:"plaintext"`
	Alg       string `json:"alg"`
	Enc       string `json:"enc"`
	// Set when the key is one the test cannot know in advance.
	RsaN string `json:"rsa_n,omitempty"`
	RsaE string `json:"rsa_e,omitempty"`
	RsaD string `json:"rsa_d,omitempty"`
}

type opened struct {
	Name      string `json:"name"`
	Plaintext string `json:"plaintext"`
	Aad       string `json:"aad"`
	Error     string `json:"error"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: jose_vectors <ours.json>")
		os.Exit(2)
	}
	ours := map[string]string{}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.Unmarshal(raw, &ours); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report := map[string]interface{}{
		"version": "go-jose v4.1.9",
		"sealed":  sealAll(rsaKey),
		"opened":  openAll(ours),
		// What this library wrote, so that a test can check it still writes exactly that.
		"ours": ours,
	}
	out, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

func sealAll(rsaKey *rsa.PrivateKey) []sealed {
	plain := []byte("interop payload")
	var out []sealed
	// JWE, compact, one per key-management algorithm.
	for _, one := range []struct {
		name string
		alg  jose.KeyAlgorithm
		enc  jose.ContentEncryption
		key  interface{}
		opts *jose.EncrypterOptions
	}{
		{"go-jwe-rsa-oaep256", jose.RSA_OAEP_256, jose.A128GCM, rsaKey.Public(), nil},
		{"go-jwe-a128kw-cbc", jose.A128KW, jose.A128CBC_HS256, kek128, nil},
		{"go-jwe-dir", jose.DIRECT, jose.A256GCM, kek256, nil},
		{"go-jwe-pbes2", jose.PBES2_HS256_A128KW, jose.A128GCM, password, nil},
		{"go-jwe-gcmkw", jose.A256GCMKW, jose.A128GCM, kek256, nil},
		{"go-jwe-ecdh", jose.ECDH_ES_A128KW, jose.A128GCM, &ecKey.PublicKey, nil},
		{"go-jwe-zip", jose.A128KW, jose.A128GCM, kek128, &jose.EncrypterOptions{Compression: jose.DEFLATE}},
	} {
		encrypter, err := jose.NewEncrypter(one.enc, jose.Recipient{Algorithm: one.alg, Key: one.key}, one.opts)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", one.name, err))
		}
		object, err := encrypter.Encrypt(plain)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", one.name, err))
		}
		token, err := object.CompactSerialize()
		if err != nil {
			panic(fmt.Sprintf("%s: %v", one.name, err))
		}
		entry := sealed{Name: one.name, Kind: "jwe-compact", Token: token, Plaintext: b64(plain), Alg: string(one.alg), Enc: string(one.enc)}
		if one.alg == jose.RSA_OAEP_256 {
			entry.RsaN = b64(rsaKey.N.Bytes())
			entry.RsaE = b64(big.NewInt(int64(rsaKey.E)).Bytes())
			entry.RsaD = b64(rsaKey.D.Bytes())
		}
		out = append(out, entry)
	}
	// JWE, JSON, with additional data and with two recipients.
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.A128KW, Key: kek128}, nil)
	if err != nil {
		panic(err)
	}
	object, err := encrypter.EncryptWithAuthData(plain, []byte(`["go-jose",2]`))
	if err != nil {
		panic(err)
	}
	out = append(out, sealed{Name: "go-jwe-aad", Kind: "jwe-json", Token: object.FullSerialize(), Plaintext: b64(plain), Alg: "A128KW", Enc: "A128GCM"})
	multi, err := jose.NewMultiEncrypter(jose.A128GCM, []jose.Recipient{
		{Algorithm: jose.A128KW, Key: kek128},
		{Algorithm: jose.A256GCMKW, Key: kek256},
	}, nil)
	if err != nil {
		panic(err)
	}
	object, err = multi.Encrypt(plain)
	if err != nil {
		panic(err)
	}
	out = append(out, sealed{Name: "go-jwe-multi", Kind: "jwe-json", Token: object.FullSerialize(), Plaintext: b64(plain), Alg: "A128KW,A256GCMKW", Enc: "A128GCM"})

	// JWS: one of each serialisation.
	for _, one := range []struct {
		name string
		alg  jose.SignatureAlgorithm
		key  interface{}
		opts *jose.SignerOptions
	}{
		{"go-jws-rs256", jose.RS256, rsaKey, nil},
		{"go-jws-es256-json", jose.ES256, ecKey, nil},
	} {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: one.alg, Key: one.key}, one.opts)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", one.name, err))
		}
		object, err := signer.Sign([]byte(`{"iss":"go-jose"}`))
		if err != nil {
			panic(fmt.Sprintf("%s: %v", one.name, err))
		}
		kind, token := "jws-compact", ""
		if one.name == "go-jws-es256-json" {
			kind, token = "jws-json", object.FullSerialize()
		} else {
			token, err = object.CompactSerialize()
			if err != nil {
				panic(err)
			}
		}
		entry := sealed{Name: one.name, Kind: kind, Token: token, Plaintext: b64([]byte(`{"iss":"go-jose"}`)), Alg: string(one.alg)}
		if one.alg == jose.RS256 {
			entry.RsaN = b64(rsaKey.N.Bytes())
			entry.RsaE = b64(big.NewInt(int64(rsaKey.E)).Bytes())
			entry.RsaD = b64(rsaKey.D.Bytes())
		}
		out = append(out, entry)
	}
	// JWS with the payload unencoded (RFC 7797), in the flattened serialisation.
	b64Signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hmackey},
		(&jose.SignerOptions{}).WithBase64(false),
	)
	if err != nil {
		panic(fmt.Sprintf("b64 signer: %v", err))
	}
	signed, err := b64Signer.Sign([]byte("$.02"))
	if err != nil {
		panic(fmt.Sprintf("b64 sign: %v", err))
	}
	out = append(out, sealed{Name: "go-jws-b64", Kind: "jws-flat", Token: signed.FullSerialize(), Plaintext: b64([]byte("$.02")), Alg: "HS256"})
	return out
}

func openAll(ours map[string]string) []opened {
	var out []opened
	record := func(name string, plain []byte, aad []byte, err error) {
		entry := opened{Name: name}
		if err != nil {
			entry.Error = err.Error()
		} else {
			entry.Plaintext = b64(plain)
			entry.Aad = string(aad)
		}
		out = append(out, entry)
	}
	keys := []jose.SignatureAlgorithm{jose.HS256, jose.ES256, jose.RS256}
	algs := []jose.KeyAlgorithm{jose.DIRECT, jose.A128KW, jose.A256GCMKW, jose.PBES2_HS256_A128KW, jose.ECDH_ES_A128KW, jose.RSA_OAEP_256}
	encs := []jose.ContentEncryption{jose.A128GCM, jose.A256GCM, jose.A128CBC_HS256}
	names := make([]string, 0, len(ours))
	for name := range ours {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		token := ours[name]
		switch {
		case name == "jws-hs256":
			object, err := jose.ParseSigned(token, keys)
			if err != nil {
				record(name, nil, nil, err)
				continue
			}
			plain, err := object.Verify(hmackey)
			record(name, plain, nil, err)
		case name == "jws-es256-flat":
			object, err := jose.ParseSigned(token, keys)
			if err != nil {
				record(name, nil, nil, err)
				continue
			}
			plain, err := object.Verify(&ecKey.PublicKey)
			record(name, plain, nil, err)
		case name == "jws-b64-false":
			plain, err := jose.ParseDetached(token, []byte("$.02"), keys)
			if err != nil {
				record(name, nil, nil, err)
				continue
			}
			got, err := plain.Verify(hmackey)
			record(name, got, nil, err)
		case name == "jwe-a128kw-json-aad":
			object, err := jose.ParseEncryptedJSON(token, algs, encs)
			if err != nil {
				record(name, nil, nil, err)
				continue
			}
			plain, err := object.Decrypt(kek128)
			record(name, plain, object.GetAuthData(), err)
		default:
			object, err := jose.ParseEncrypted(token, algs, encs)
			if err != nil {
				record(name, nil, nil, err)
				continue
			}
			key := map[string]interface{}{
				"jwe-dir-compact":        mustHex("000102030405060708090a0b0c0d0e0f"),
				"jwe-a128kw-compact":     kek128,
				"jwe-gcmkw-compact":      kek256,
				"jwe-pbes2-compact":      password,
				"jwe-ecdh-kw-compact":    peerKey,
			}[name]
			plain, err := object.Decrypt(key)
			record(name, plain, nil, err)
		}
	}
	return out
}
