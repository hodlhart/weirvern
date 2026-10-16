// Extract the synthetic payloads the UI harness defines, so the demo server can serve the REAL
// console against fake data (RFC 5737 addresses) for the README screenshots.
//
// Why extract instead of re-typing: the harness payloads are what the frontend is PROVEN against.
// A hand-written second copy would drift, and a screenshot rendered from a drifted payload proves
// nothing about the shipped renderer.
"use strict";
const fs = require("fs");
const path = require("path");

const SRC = fs.readFileSync(path.resolve(__dirname, "..", "scripts", "jsdom_render.js"), "utf8");
const WANT = process.argv.slice(2);
const OUT = path.resolve(__dirname, "..", "docs", "demo");

function extract(name) {
  const start = SRC.indexOf(`const ${name} = `);
  if (start < 0) return null;
  let i = start + `const ${name} = `.length;
  let depth = 0;
  for (; i < SRC.length; i++) {
    const c = SRC[i];
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i++;
      while (i < SRC.length) {
        if (SRC[i] === "\\") { i += 2; continue; }
        if (SRC[i] === q) break;
        // Template literals can contain ${...}; the payloads do not use them, and treating the
        // whole literal as opaque would mis-count braces if they did -- so assert instead.
        i++;
      }
      continue;
    }
    if (c === "/" && SRC[i + 1] === "/") { while (i < SRC.length && SRC[i] !== "\n") i++; continue; }
    if (c === "/" && SRC[i + 1] === "*") { i = SRC.indexOf("*/", i) + 1; continue; }
    if (c === "{" || c === "[") depth++;
    if (c === "}" || c === "]") { depth--; if (depth === 0) break; }
  }
  const text = SRC.slice(start + `const ${name} = `.length, i + 1);
  return text;
}

const chunks = [];
const found = [];
for (const name of WANT) {
  const text = extract(name);
  if (!text) { console.log(`  MISSING: ${name}`); continue; }
  if (text.includes("${")) { console.log(`  TEMPLATE in ${name}: needs manual handling`); continue; }
  chunks.push(`const ${name} = ${text};`);
  found.push(name);
}
const body = chunks.join("\n") + `\nreturn { ${found.join(", ")} };`;
const objs = new Function(body)();

fs.mkdirSync(OUT, { recursive: true });
for (const name of found) {
  const file = path.join(OUT, name.toLowerCase().replace(/_payload|_state|_stub/g, "") + ".json");
  fs.writeFileSync(file, JSON.stringify(objs[name], null, 2) + "\n");
  console.log(`  ${name} -> ${path.relative(process.cwd(), file)}`);
}
