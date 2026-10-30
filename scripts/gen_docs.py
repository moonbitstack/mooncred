#!/usr/bin/env python3
"""Write the generated parts of the site.

* docs/api.html, from each package's pkg.generated.mbti, the head comment of
  its moon.pkg and the /// comments in its sources;
* the listings and transcripts of docs/guide.html, cut from and printed by
  src/examples/guide;
* the version, package and test counts on docs/index.html.

    moon info --target all
    python3 scripts/gen_docs.py            write all three
    python3 scripts/gen_docs.py --check    exit 1 if any page is out of date
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
DOCS = ROOT / "docs"
GUIDE = "src/examples/guide"

# Reading order: tokens first, the formats a web service meets daily, then
# certificates and what travels with them, then the binary formats.
PACKAGES = ["jwt", "jwk", "jwe", "token", "x509", "csr", "pbe", "pkcs12", "revoke", "policy", "cose", "cbor", "roots"]

# Plumbing that `derive` adds: public, but not what a reader came for.
DERIVED = {"equal", "not_equal", "to_repr", "op_equal", "to_string", "hash", "output"}

KIND = {"fn": "fn", "value": "let", "struct": "type", "enum": "type", "error": "error", "trait": "trait", "alias": "type", "opaque": "type"}

ROMAN = ["i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii", "xiii", "xiv", "xv", "xvi"]


def esc(text: str) -> str:
    return html.escape(text, quote=False)


# ── interfaces ────────────────────────────────────────────────────────────


def parse_mbti(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    decls: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.startswith(("//", "package ", "import", "}", "  \"")):
            i += 1
            continue
        block: list[str] = []
        depth = 0
        while i < len(lines):
            block.append(lines[i])
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
            nxt = lines[i] if i < len(lines) else ""
            if depth <= 0 and (not nxt.strip() or nxt.startswith("//") or re.match(r"^(pub|type|priv)\b", nxt)):
                break
        decl = classify("\n".join(block).strip())
        if decl:
            decls.append(decl)
    return decls


def classify(text: str) -> dict | None:
    first = text.splitlines()[0]
    patterns = [
        ("fn", r"pub(?:\([a-z]+\))?\s+fn(?:\[[^\]]*\])?\s+([A-Za-z0-9_:]+)"),
        ("value", r"pub\s+let\s+([A-Za-z0-9_]+)"),
        ("error", r"pub(?:\([a-z]+\))?\s+suberror\s+([A-Za-z0-9_]+)"),
        ("struct", r"pub(?:\([a-z]+\))?\s+struct\s+([A-Za-z0-9_]+)"),
        ("enum", r"pub(?:\([a-z]+\))?\s+enum\s+([A-Za-z0-9_]+)"),
        ("trait", r"pub(?:\([a-z]+\))?\s+trait\s+([A-Za-z0-9_]+)"),
        ("alias", r"pub(?:\([a-z]+\))?\s+typealias\s+.*?([A-Za-z0-9_]+)\s*$"),
        ("opaque", r"type\s+([A-Za-z0-9_]+)"),
    ]
    for kind, pattern in patterns:
        m = re.match(pattern, first)
        if m:
            return {"kind": kind, "name": m.group(1), "sig": text, "open": "(all)" in first}
    m = re.match(r"pub\s+impl\s+(.+)", first)
    if m:
        return {"kind": "impl", "name": "", "sig": m.group(1).strip()}
    return None


def fold(decls: list[dict]) -> list[dict]:
    """Fold `impl X for Y` into Y, and drop what `derive` wrote."""
    named = {d["name"]: d for d in decls if d["kind"] != "impl"}
    for decl in decls:
        m = decl["kind"] == "impl" and re.match(r"(.+?)\s+for\s+([A-Za-z0-9_]+)", decl["sig"])
        if m and m.group(2) in named:
            named[m.group(2)].setdefault("impls", []).append(m.group(1).strip())
    kept = []
    for decl in decls:
        if decl["kind"] == "impl":
            continue
        if decl["kind"] == "fn" and decl["name"].split("::")[-1] in DERIVED and "::" in decl["name"]:
            continue
        kept.append(decl)
    return kept


# ── comments ──────────────────────────────────────────────────────────────


def paragraphs(lines: list[str]) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    for line in lines:
        if line:
            current.append(line)
        elif current:
            out.append(" ".join(current))
            current = []
    if current:
        out.append(" ".join(current))
    return out


def parse_docs(package: Path) -> dict[str, list[str]]:
    docs: dict[str, list[str]] = {}
    for file in sorted(package.glob("*.mbt")):
        if file.name.endswith("test.mbt"):
            continue
        lines = file.read_text(encoding="utf-8").splitlines()
        # A method lent by a trait has its comment on the trait; say which.
        for line in lines:
            m = re.match(r"pub extend ([A-Za-z0-9_]+) with ([@A-Za-z0-9_.]+)::\{([^}]*)\}", line)
            if m and m.group(2) not in {"Eq", "Debug", "Show", "Hash", "Compare"}:
                for method in (s.strip() for s in m.group(3).split(",")):
                    docs.setdefault(f"{m.group(1)}::{method}", [f"`{m.group(2)}`'s `{method}`, callable on the value directly."])
        i = 0
        while i < len(lines):
            if not lines[i].startswith("///|"):
                i += 1
                continue
            block: list[str] = []
            i += 1
            while i < len(lines) and lines[i].startswith("///"):
                block.append(lines[i][3:].strip())
                i += 1
            while i < len(lines) and (not lines[i].strip() or lines[i].startswith("#")):
                i += 1
            if i >= len(lines):
                break
            name = decl_name(lines[i])
            text = [p for p in paragraphs(block) if not p.startswith("```")]
            if name and text and name not in docs:
                docs[name] = text
    return docs


def decl_name(line: str) -> str | None:
    m = re.search(r"pub(?:\([a-z]+\))?\s+fn(?:\[[^\]]*\])?\s+([A-Za-z0-9_:]+)", line)
    if m:
        return m.group(1)
    m = re.match(r"(?:pub(?:\([a-z]+\))?\s+)?(?:suberror|struct|enum|trait|typealias)\s+([A-Za-z0-9_]+)", line)
    if m:
        return m.group(1)
    m = re.search(r"pub\s+let\s+([A-Za-z0-9_]+)", line) or re.match(r"(?:pub\s+)?type\s+([A-Za-z0-9_]+)", line)
    return m.group(1) if m else None


def head_comment(package: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """The moon.pkg head: specification lines `Title, RFC n: url`, then prose."""
    lines: list[str] = []
    for line in (package / "moon.pkg").read_text(encoding="utf-8").splitlines():
        if not line.startswith("//"):
            break
        lines.append(line[2:].strip())
    blocks = "\n".join(lines).split("\n\n")
    specs = []
    for line in blocks[0].splitlines():
        m = re.match(r"(.+?):\s+(https?://\S+)$", line)
        specs.append((m.group(1), m.group(2)) if m else (line, ""))
    prose = paragraphs("\n".join(blocks[1:]).splitlines())
    return specs, prose


def title_of(specs: list[tuple[str, str]]) -> str:
    text = specs[0][0] if specs else ""
    return re.split(r",\s*(?:RFC|PKCS)|:", text)[0].strip()


# ── the reference page ────────────────────────────────────────────────────


def code_inline(text: str) -> str:
    """`code` in a doc comment becomes <code>."""
    parts = re.split(r"(`[^`]+`)", text)
    return "".join("<code>" + esc(p[1:-1]) + "</code>" if p.startswith("`") else esc(p) for p in parts)


def render_item(decl: dict, docs: dict[str, list[str]], anchor: str) -> str:
    parts = decl["name"].split("::")
    label = esc(parts[-1]) if len(parts) == 1 else '<span class="dim">' + esc("::".join(parts[:-1])) + "::</span>" + esc(parts[-1])
    sig = decl["sig"]
    if decl["kind"] == "struct" and not decl["open"]:
        sig = sig.splitlines()[0]
    out = [f'<div class="item" id="{anchor}">', f'<div class="name"><span class="kind">{KIND[decl["kind"]]}</span>{label}</div>',
           f'<pre class="sig"><code>{esc(sig)}</code></pre>']
    out += [f"<p>{code_inline(p)}</p>" for p in docs.get(decl["name"], [])]
    if decl.get("impls"):
        out.append('<div class="impls">implements ' + ", ".join(esc(t) for t in decl["impls"]) + "</div>")
    out.append("</div>")
    return "\n".join(out)


def sort_key(decl: dict) -> tuple:
    order = {"error": 0, "trait": 1, "struct": 2, "enum": 2, "opaque": 2, "alias": 2, "value": 3, "fn": 4}
    owner = decl["name"].split("::")[0] if "::" in decl["name"] else ""
    return (order[decl["kind"]] if not owner else 4, owner, decl["name"].lower())


def reference(version: str) -> tuple[str, int, int]:
    sheets = []
    rows = []
    total = 0
    for n, name in enumerate(PACKAGES, start=2):
        package = SRC / name
        decls = sorted(fold(parse_mbti(package / "pkg.generated.mbti")), key=sort_key)
        docs = parse_docs(package)
        specs, prose = head_comment(package)
        total += len(decls)
        rows.append(f'<a href="#{name}"><span class="pkg">{name}</span><span class="what">{esc(title_of(specs))}</span>'
                    f'<span class="count">{len(decls)}</span></a>')
        spec_html = " · ".join(f'<a href="{esc(url)}">{esc(t)}</a>' if url else esc(t) for t, url in specs)
        types = [d for d in decls if d["kind"] != "fn" or "::" not in d["name"]]
        toc = " ".join(f'<a href="#{name}-{d["name"].replace("::", "-")}">{esc(d["name"])}</a>' for d in types)
        items = "\n".join(render_item(d, docs, f'{name}-{d["name"].replace("::", "-")}') for d in decls)
        sheets.append(f"""  <article class="sheet" id="{name}">
    <header class="lh"><span class="name">Mooncred</span><span class="spacer"></span><span>@{name}</span><span class="folio">{ROMAN[n - 1]}</span></header>
    <h2>{name}</h2>
    <p class="spec">{spec_html}</p>
{"".join(f"    <p>{code_inline(p)}</p>" + chr(10) for p in prose)}    <p class="toc">{toc}</p>
{items}
    <footer class="foot"><span>moonbitstack/mooncred/{name}</span><span class="dot"></span><span>{len(decls)} entries</span><a class="next" href="#contents">contents</a></footer>
  </article>""")
    contents = f"""  <article class="sheet" id="contents">
    <header class="lh"><span class="name">Mooncred</span><span class="spacer"></span><span>the reference</span><span class="folio">i</span></header>
    <h1>The reference, <em>by package.</em></h1>
    <p>Every public type, function and value of mooncred {esc(version)}, read from each package's interface and the comments above its definitions. The <a href="guide.html">guide</a> shows them at work.</p>
    <nav class="pkgs" aria-label="Packages">
      {(chr(10) + "      ").join(rows)}
    </nav>
    <footer class="foot"><span>{len(PACKAGES)} packages</span><span class="dot"></span><span>{total} entries</span><span class="dot"></span><span>generated by scripts/gen_docs.py</span></footer>
  </article>"""
    template = (DOCS / "api.template.html").read_text(encoding="utf-8")
    page = template.replace("<!-- sheets -->", contents + "\n\n" + "\n\n".join(sheets))
    return page, total, len(PACKAGES)


# ── the guide ─────────────────────────────────────────────────────────────


def listings() -> dict[str, str]:
    source = (ROOT / GUIDE / "main.mbt").read_text(encoding="utf-8").splitlines()
    out: dict[str, str] = {}
    name = None
    body: list[str] = []
    for line in source:
        m = re.match(r"\s*// @@listing (\w+)", line)
        if m:
            name, body = m.group(1), []
        elif name and line.strip() == "// @@end":
            indent = min(len(l) - len(l.lstrip()) for l in body if l.strip())
            out[name] = "\n".join(l[indent:] for l in body)
            name = None
        elif name:
            body.append(line)
    return out


def highlight(code: str) -> str:
    return "\n".join(f'<span class="c">{esc(l)}</span>' if l.lstrip().startswith("//") else esc(l) for l in code.split("\n"))


def transcript() -> dict[str, str]:
    run = subprocess.run(["moon", "run", GUIDE, "--target", "native"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    if run.returncode != 0:
        sys.exit(f"moon run {GUIDE} failed:\n{run.stderr or run.stdout}")
    out: dict[str, list[str]] = {}
    current = None
    for line in run.stdout.splitlines():
        if line.startswith("@@"):
            current = line[2:].strip()
            out[current] = []
        elif current:
            out[current].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def slot(page: str, kind: str, name: str, body: str) -> str:
    opening, closing = f"<!-- {kind}:{name} -->", f"<!-- /{kind}:{name} -->"
    if opening not in page:
        sys.exit(f"docs/guide.html has no {kind} slot for {name!r}")
    head, _, rest = page.partition(opening)
    _, _, tail = rest.partition(closing)
    return head + opening + body + closing + tail


def guide() -> str:
    page = (DOCS / "guide.html").read_text(encoding="utf-8")
    code, runs = listings(), transcript()
    if set(code) != set(runs):
        sys.exit(f"listings and transcripts differ: {sorted(set(code) ^ set(runs))}")
    for name in code:
        page = slot(page, "code", name, highlight(code[name]))
        page = slot(page, "run", name, esc(runs[name]))
    left = re.findall(r"<!-- (?:code|run):(\w+) -->", page)
    missing = sorted(set(left) - set(code))
    if missing:
        sys.exit(f"docs/guide.html has slots nothing fills: {missing}")
    return page


# ── the opening page ──────────────────────────────────────────────────────


def tests() -> int:
    return sum(len(re.findall(r"^test ", f.read_text(encoding="utf-8"), re.M)) for f in SRC.rglob("*test.mbt"))


def index(values: dict[str, str]) -> str:
    page = (DOCS / "index.html").read_text(encoding="utf-8")
    for key, value in values.items():
        page = re.sub(rf'(<[a-z]+ data-fill="{key}">)[^<]*(</[a-z]+>)', rf"\g<1>{value}\g<2>", page)
    return page


def main() -> None:
    check = "--check" in sys.argv[1:]
    version = re.search(r'^version = "([^"]+)"', (ROOT / "moon.mod").read_text(encoding="utf-8"), re.M).group(1)
    api, entries, packages = reference(version)
    pages = {
        DOCS / "api.html": api,
        DOCS / "guide.html": guide(),
        DOCS / "index.html": index({"version": version, "packages": str(packages), "tests": str(tests())}),
    }
    stale = []
    for path, text in pages.items():
        before = path.read_text(encoding="utf-8") if path.exists() else ""
        if before != text:
            stale.append(path.relative_to(ROOT).as_posix())
            if not check:
                path.write_text(text, encoding="utf-8", newline="\n")
    if check and stale:
        sys.exit("out of date: " + ", ".join(stale) + "; run python3 scripts/gen_docs.py")
    print(("up to date" if not stale else "wrote " + ", ".join(stale)) + f" ({packages} packages, {entries} entries)")


if __name__ == "__main__":
    main()
