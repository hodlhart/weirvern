# JA4 (TLS client fingerprinting) options. BSD-3-Clause; see LICENSE-JA4.
module FINGERPRINT;

export {
  option delimiter: string = "_";

  # BSD licensed
  option JA4_enabled:    bool = T;
  option JA4_raw:        bool = F;

}
