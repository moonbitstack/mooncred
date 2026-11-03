// The desk: what the page sends the library, and how it draws the answer back.
//
// The engine is built by .github/workflows/docs.yml from src/examples/browser and is not in the
// repository, so the first press of the seal fetches it and nothing before that does.

const $ = (id) => document.getElementById(id);
const report = $("report");
const note = $("engine");

let engine = null;

const load = async () => {
  if (engine) return engine;
  note.textContent = "fetching the library…";
  engine = await import(new URL("../engine/mooncred.js", import.meta.url));
  note.textContent = "";
  return engine;
};

// A certificate this library wrote: `moon run src/examples/pqc`, from a seed fixed in that
// program. It is the page's sample input, not a recorded answer.
const SAMPLE_CERT = `-----BEGIN CERTIFICATE-----
MIIVSjCCCEegAwIBAgIBATALBglghkgBZQMEAxIwFjEUMBIGA1UEAwwLcHFjLmV4
YW1wbGUwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAWMRQwEgYDVQQD
DAtwcWMuZXhhbXBsZTCCB7IwCwYJYIZIAWUDBAMSA4IHoQBIaD2Rl44x6z3duLBH
NILSuIpfYllJ/Y9YpWHmlr1MJ9BbONuy7fAeZk79gb4eqJNojOaKotUcWVj4u8br
TonuZ9LAMglU1XISyscin/HW6vA5KL1RUR+NiNhHc2x94nMNWXjlQQcTFgl4hncR
v1U5oL/Ew1DCvlcrrw7i4vsWzP6ggCjZmsSa67dZN93OERzati//POqLoiM9Hlb7
xcWh5ybeY/rdKvAWsRkXf6PZcaLZJ3Fz/OVbZ3Ra8LfCHVl9vrk+ajLzQcSaWovp
6CUIjR8qpFFV1siuFTZ+TrADuP33hRBxlJc5+f/wkCPq9FEE0qhKRZBu7UZxpE3C
jSeYe7Vd9p6ehWH2GoCnJplQOGX+2bfucqjhehnECBRPSymv73Axw6bYVxYQtCyf
QhJFqI8ZfhaBKwMRWbZblofls+k0xSJa6Yp5unPSs5nXNRDv+tGeU7hFDwuo/OEB
L9mNJgp0qqoT+uJJoAaxw09boLiC8mN4Ii+zbyKDwkPw/+tfG7QUoKcNVePUCla2
y8iK4fA7eyiC2Y3uoo4UXJ3t/Y6vHO8u2UqLBQ+JZPRtHqDQwqQ+Ddphgq2/T27R
dbZ0IleFm/IvOkF+zx+diTF7XlOdWHrxa54TE+BFFP+mS6iz/yuDIfiBHLP7AiyP
ZE5wpLgKL7/uYEq7c3kJHqjmxcdN/AKDZmtAwHk4cAKCBKE2v12pVo63mNNJA4vb
DBHgNEXnhHy1Bpx1zyisYBx3mdlYIQ3byyJuUa/vnx3kewc4c9bT+XRWvt4IUILn
SimLLNSPSzCTFV82bI+mAcavhY36MsCEkbKimIf5AzWUml1u2qZ5iCo6lda/bZcK
Ih9LnT2MvzhK+BqsleKzKU4EeJrINyel3ARVn5avQdigU1Fv7u68UnRutqsoGeCR
CHENg18BH6YwZYcq0zTVzf+ysjEFB+kvyZOuMX2pf08wnNrw9n7ZnZAhVXYIOEn5
U7JG1/7bP9tnZ5hQpa1ATmQUf7fPT2rt3QWvtLg0lo0f6IAUlg3OXZQiNlJuEqR4
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
-----END CERTIFICATE-----`;

// A token signed with the secret below, expiring in 2036: move the instant past that and the
// verdict changes, which is the point of showing the clock.
const SAMPLE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtb29uYml0c3RhY2siLCJzdWIiOiJoZWtlMTIyOCIsImF1ZCI6InRoZSBkZXNrIiwiaWF0IjoxNzkzMjMyMDAwLCJleHAiOjIwODI3NTg0MDB9.HW3qBU9knnNbvt4P0tGJ_EN8lTZDDV9Ff-3L1JxnoZM";
const SAMPLE_SECRET = "correct horse battery staple";

const stamp = (seconds) => new Date(seconds * 1000).toISOString().replace("T", " ").slice(0, 19) + "Z";

const kv = (rows) => {
  const dl = document.createElement("dl");
  dl.className = "kv";
  for (const [key, value] of rows) {
    if (value === undefined || value === null || value === "" || (Array.isArray(value) && !value.length)) continue;
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = Array.isArray(value) ? value.join(", ") : value;
    dl.append(dt, dd);
  }
  return dl;
};

const card = (title, index, rows) => {
  const box = document.createElement("div");
  box.className = "card";
  const h = document.createElement("h3");
  if (index !== null) {
    const i = document.createElement("span");
    i.className = "i";
    i.textContent = index === 0 ? "leaf" : "issuer " + index;
    h.append(i);
  }
  h.append(document.createTextNode(title));
  box.append(h, kv(rows));
  return box;
};

const verdict = (v, kind) => {
  const box = document.createElement("div");
  box.className = "verdict " + (v.ok ? "ok" : "no");
  const p = document.createElement("p");
  p.textContent = v.line;
  box.append(p);
  const code = document.createElement("span");
  code.className = "code";
  code.textContent = v.reason
    ? v.reason.code + (v.reason.at === undefined ? "" : " · " + v.reason.at)
    : v.ok
      ? (kind === "token" ? "signature and times agree" : "a path to the anchor")
      : "not checked";
  box.append(code);
  return box;
};

const draw = (data) => {
  report.replaceChildren();
  report.append(verdict(data.verdict, data.kind));

  if (data.certs && data.certs.length) {
    const cards = document.createElement("div");
    cards.className = "cards";
    data.certs.forEach((c, i) => {
      cards.append(card(c.subject, i, [
        ["issuer", c.issuer],
        ["from", stamp(c.from)],
        ["to", stamp(c.to)],
        ["signature", c.alg],
        ["key", c.key],
        ["names", c.sans],
        ["", c.ca ? "a CA: it may issue" : ""],
      ]));
    });
    report.append(cards);
  }

  if (data.kind === "token") {
    const cards = document.createElement("div");
    cards.className = "cards";
    cards.append(
      card("the header", null, data.header.map((e) => [e.name, e.value])),
      card("the claims", null, data.claims.map((e) => [
        e.name,
        ["exp", "iat", "nbf", "auth_time", "updated_at"].includes(e.name) && /^\d+$/.test(e.value)
          ? e.value + "   (" + stamp(Number(e.value)) + ")"
          : e.value,
      ])),
    );
    report.append(cards);
  }
};

const instant = () => {
  const value = $("when").value;
  if (!value) return Math.floor(Date.now() / 1000);
  return Math.floor(new Date(value).getTime() / 1000);
};

const run = async () => {
  const raw = $("cred").value.trim();
  report.replaceChildren();
  if (!raw) {
    note.textContent = "nothing to read yet";
    return;
  }
  let library;
  try {
    library = await load();
  } catch (e) {
    note.textContent = "the engine could not be loaded: " + e;
    return;
  }
  const isToken = !raw.includes("-----BEGIN") && raw.split(".").length === 3;
  let json;
  try {
    json = isToken
      ? library.token(raw, $("secret").value, instant())
      : library.certificate(raw, $("host").value.trim(), instant(), $("trust").checked);
  } catch (e) {
    note.textContent = "the library stopped: " + e;
    return;
  }
  note.textContent = "";
  draw(JSON.parse(json));
};

$("form").addEventListener("submit", (event) => {
  event.preventDefault();
  run();
});

$("ex-cert").addEventListener("click", () => {
  $("cred").value = SAMPLE_CERT;
  $("host").value = "pqc.example";
  $("secret").value = "";
  $("trust").checked = true;
  run();
});

$("ex-token").addEventListener("click", () => {
  $("cred").value = SAMPLE_TOKEN;
  $("host").value = "";
  $("secret").value = SAMPLE_SECRET;
  run();
});

const now = new Date();
now.setSeconds(0, 0);
const pad = (n) => String(n).padStart(2, "0");
$("when").value =
  now.getFullYear() + "-" + pad(now.getMonth() + 1) + "-" + pad(now.getDate()) +
  "T" + pad(now.getHours()) + ":" + pad(now.getMinutes());
