#!/usr/bin/env python3
"""Run the C2SP x509-limbo suite against `x509.verify`.

The suite is a single file at a pinned commit, checked by digest before it is used, and
fed to `src/tools/limbo` on standard input. That program prints one line per case this
library judges differently from the suite, and this script compares those lines with the
list below: every divergence is a rule this library states and does not follow, written
down in README's "Conformance" section. A case that newly disagrees, or one listed here
that starts agreeing, fails the run.

    python3 scripts/limbo.py             run, downloading the suite once
    python3 scripts/limbo.py --refresh   discard the copy and download it again
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "_build" / "limbo" / "limbo.json"

# C2SP/x509-limbo at 2026-11-02. The digest is of the file that commit ships, so a
# rewritten tag or a branch that moved cannot change what CI judged.
COMMIT = "519f4bcf6a31d20e1b7011a0586e233dbbd3e732"
DIGEST = "56799cefd65fc9e0bdb9cb0f97fce6734533b45df3de4fc17fdc7b7b79654fca"
URL = f"https://raw.githubusercontent.com/C2SP/x509-limbo/{COMMIT}/limbo.json"

# The cases this validator judges differently, grouped by the rule behind the difference.
# README's "Conformance" section carries the same groups.
DIVERGENCES: dict[str, list[str]] = {
    "the trusted anchor is a name and a key, so its own validity, extensions and criticality are not examined": [
        "rfc5280::aki::critical-aki",
        "rfc5280::aki::cross-signed-root-missing-aki",
        "rfc5280::nc::permitted-dns-match-noncritical",
        "rfc5280::root-inconsistent-ca-extensions",
        "rfc5280::root-missing-basic-constraints",
        "rfc5280::root-non-critical-basic-constraints",
        "rfc5280::ski::root-missing-ski",
        "rfc5280::unknown-critical-extension-root",
        "rfc5280::validity::expired-root",
        "webpki::aki::root-with-aki-all-fields",
        "webpki::aki::root-with-aki-authoritycertissuer",
        "webpki::aki::root-with-aki-authoritycertserialnumber",
        "webpki::aki::root-with-aki-missing-keyidentifier",
        "webpki::aki::root-with-aki-ski-mismatch",
        "webpki::eku::root-has-eku",
    ],
    "a leaf certificate that is itself a CA is refused": [
        "pathlen::validation-ignores-pathlen-in-leaf",
        "rfc5280::ca-as-leaf",
    ],
    "the profile rules that decide how a certificate may be issued, rather than whether a path is trustworthy": [
        "webpki::cn::case-mismatch",
        "webpki::cn::ipv4-hex-mismatch",
        "webpki::cn::ipv4-leading-zeros-mismatch",
        "webpki::cn::ipv6-non-rfc5952-mismatch",
        "webpki::cn::ipv6-uncompressed-mismatch",
        "webpki::cn::ipv6-uppercase-mismatch",
        "webpki::cn::not-in-san",
        "webpki::cn::punycode-not-in-san",
        "webpki::cn::utf8-vs-punycode-mismatch",
        "webpki::eku::ee-anyeku",
        "webpki::eku::ee-critical-eku",
        "webpki::eku::ee-without-eku",
        "webpki::malformed-aia",
        "webpki::san::public-suffix-multi-label-wildcard-san",
        "webpki::san::public-suffix-private-namespace-wildcard-san",
        "webpki::san::san-critical-with-nonempty-subject",
    ],
    "an authority key identifier or a subject key identifier the path algorithm never reads": [
        "rfc5280::aki::intermediate-missing-aki",
        "rfc5280::aki::leaf-missing-aki",
        "rfc5280::ski::critical-ski",
        "rfc5280::ski::intermediate-missing-ski",
    ],
    "the strength of the key that signs, which this validator holds to `policy.bits`, and not the shape of the key the leaf carries": [
        "webpki::forbidden-dsa-leaf",
        "webpki::forbidden-p192-leaf",
        "webpki::forbidden-rsa-key-not-divisible-by-8-in-leaf",
        "webpki::forbidden-rsa-not-divisible-by-8-in-root",
        "webpki::forbidden-weak-rsa-in-leaf",
    ],
    "the issuance rules for a certificate's own extensions, which a validator is not asked to audit": [
        "rfc5280::ca-empty-subject",
        "rfc5280::leaf-ku-keycertsign",
        "rfc5280::nc::not-allowed-in-ee-critical",
        "rfc5280::nc::not-allowed-in-ee-noncritical",
        "rfc5280::pc::ica-noncritical-pc",
        "rfc5280::san::noncritical-with-empty-subject",
        "rfc5280::san::underscore-dns",
        "rfc5280::serial::too-long",
        "rfc5280::serial::zero",
    ],
    "a constraint written with a leading period, read as every name below it": [
        "rfc5280::nc::invalid-dnsname-leading-period",
    ],
}

DOCUMENTED = {case for cases in DIVERGENCES.values() for case in cases}


def suite(refresh: bool) -> Path:
    if refresh or not CACHE.exists():
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        print(f"downloading x509-limbo at {COMMIT[:12]}", flush=True)
        with urllib.request.urlopen(URL, timeout=120) as response:
            CACHE.write_bytes(response.read())
    digest = hashlib.sha256(CACHE.read_bytes()).hexdigest()
    if digest != DIGEST:
        sys.exit(f"{CACHE} is not the pinned suite: sha256 {digest}, expected {DIGEST}")
    return CACHE


def run() -> tuple[str, set[str]]:
    with suite("--refresh" in sys.argv[1:]).open("rb") as feed:
        done = subprocess.run(
            ["moon", "run", "src/tools/limbo", "--target", "native"],
            cwd=ROOT,
            stdin=feed,
            capture_output=True,
        )
    out = done.stdout.decode("utf-8", "replace")
    if done.returncode not in (0, 1):
        sys.exit("the runner could not read the suite:\n" + out + done.stderr.decode("utf-8", "replace"))
    summary = next((line for line in out.splitlines() if line.startswith("limbo:")), "")
    disagreed = {m.group(1) for m in re.finditer(r"^DISAGREE (\S+):", out, re.M)}
    return summary, disagreed


def main() -> None:
    summary, disagreed = run()
    print(summary)
    new = sorted(disagreed - DOCUMENTED)
    stale = sorted(DOCUMENTED - disagreed)
    for case in new:
        print(f"new divergence: {case}")
    for case in stale:
        print(f"divergence gone, remove it from scripts/limbo.py and README: {case}")
    if new or stale:
        sys.exit(f"the suite and the documented divergences differ: {len(new)} new, {len(stale)} gone")
    print(f"{len(disagreed)} documented divergences, as expected")


if __name__ == "__main__":
    main()
