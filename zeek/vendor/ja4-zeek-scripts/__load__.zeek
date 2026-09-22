# Loader for the vendored JA4 module (BSD-3-Clause; see LICENSE-JA4 in this directory).
module FINGERPRINT;

export { type Info: record {}; }
redef record connection += { fp: FINGERPRINT::Info &optional; };

@load ./config
@load ./ja4
