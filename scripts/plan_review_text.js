#!/usr/bin/env node
/* What the console SAYS about a staged intercept plan, printed as JSON for a test to pin.
 *
 * THE SOURCE IS THE SHIPPING app.js. The two functions below are extracted from it by name and
 * evaluated here, never copied: a test against a copy passes when the product is wrong, which is
 * the defect the controls were written to avoid. If the functions are renamed, this script fails
 * loudly instead of silently testing nothing.
 *
 * WHY: the staged list used to print the plan's stored JSON verbatim. An operator editing eth2 saw
 * `{"eth1":...}` first and concluded the change was aimed at the wrong port (operator report,
 * 2026-11-18). The review must say which NIC moves and what it becomes.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const APP = path.resolve(__dirname, "..", "weirvern", "admin", "web", "app.js");
const src = fs.readFileSync(APP, "utf8");

function extract(name) {
  const start = src.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`${name} is not in ${APP}; the review text has no implementation`);
  let depth = 0;
  let opened = false;
  for (let i = src.indexOf("{", start); i < src.length; i += 1) {
    if (src[i] === "{") {
      depth += 1;
      opened = true;
    } else if (src[i] === "}") {
      depth -= 1;
      if (opened && depth === 0) return src.slice(start, i + 1);
    }
  }
  throw new Error(`${name} has unbalanced braces in ${APP}`);
}

/* eslint-disable no-new-func -- the point is to run the shipping text, not a copy of it */
// ONE SCOPE, SO THE TWO FUNCTIONS SEE EACH OTHER: describePlanChange calls describePlan by name.
// `new Function` keeps the declarations together; a bare eval in a CommonJS module would not.
const api = new Function(
  `${extract("describePlan")}\n${extract("describePlanChange")}\n`
  + "return { describePlan, describePlanChange };",
)();
/* eslint-enable no-new-func */
const describePlan = api.describePlan;
const describePlanChange = api.describePlanChange;

const eth1 = {
  mode: "siphon", sluice: true, segment: "192.0.2.0/24",
  addr: "192.0.2.19", gateway: "192.0.2.1", targets: "*",
};
const eth2 = {
  mode: "siphon", sluice: true, segment: "198.51.100.0/24",
  addr: "198.51.100.233", gateway: "198.51.100.1", targets: "*",
};
const before = JSON.stringify({ eth1 });
const after = JSON.stringify({ eth1, eth2 });

const out = {
  adds_eth2: describePlanChange(after, before),
  no_change: describePlanChange(after, after),
  removes_eth2: describePlanChange(before, after),
  changes_address: describePlanChange(JSON.stringify({ eth1: { ...eth1, addr: "192.0.2.20" } }), before),
  plan_all: describePlan(after, ""),
  plan_one_nic: describePlan(after, "eth2"),
  plan_absent_nic: describePlan(after, "eth3"),
  plan_empty: describePlan("{}", ""),
  plan_unparsable: describePlan("not json", ""),
};

process.stdout.write(JSON.stringify(out));
