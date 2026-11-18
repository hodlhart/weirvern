// EXTRACT `ifaceSplitText` FROM THE SHIPPING soc.js AND RUN IT.
//
// The console has no bundler, so a helper is only exercised when a browser runs it. A test
// against a copy of the function would pass while the product says something else -- the
// lesson 0.23.69 wrote down -- so this reads the real file and throws if the name is gone.
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "weirvern", "admin", "web", "soc.js"), "utf8");
const match = src.match(/function ifaceSplitText\([\s\S]*?\n}\n/);
if (!match) {
  console.error("ifaceSplitText is not in soc.js");
  process.exit(2);
}
const fn = new Function(`${match[0]}; return ifaceSplitText;`)();
const cases = JSON.parse(process.argv[2] || "[]");
console.log(JSON.stringify(cases.map((c) => fn(c))));
