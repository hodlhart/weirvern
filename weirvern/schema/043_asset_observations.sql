-- 023_asset_observations.sql
--
-- NMAP NSE IDENTITY FACTS. The active inventory's identity layer is Nmap + safe NSE scripts:
-- open ports and service banners say what is listening, while scripts such as http-title,
-- ssl-cert, smb-os-discovery and snmp-sysdescr say what the device or application calls itself.
--
-- THIS IS NOT A VULNERABILITY TABLE. A script output is an observation, not a finding. Keeping
-- it separate from asset_findings preserves the distinction between "the device says it is X"
-- and "a matcher says it is exposed to Y". Values are clipped by the scanner before insert.
CREATE TABLE IF NOT EXISTS weirvern.asset_observations
(
    asset_key       String,
    ip              String,
    port            UInt16 DEFAULT 0,
    script          LowCardinality(String),
    key             String,
    value           String,
    observed_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(observed_at)
ORDER BY (asset_key, port, script, key);
