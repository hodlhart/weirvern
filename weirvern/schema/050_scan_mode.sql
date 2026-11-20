-- 050_scan_mode.sql
--
-- WHAT KIND OF SCAN A WEIRLING CAN RUN, not just whether it has a binary.
--
-- Unprivileged Nmap can only complete a TCP connection (`--unprivileged`, connect scan); SYN
-- and UDP scans need CAP_NET_RAW/CAP_NET_ADMIN on the binary (or root). The installer grants
-- those with one `setcap`, and the agent reports the measured result so the console can say
-- "connect scans only" instead of claiming full scanning.
--
-- `can_install` is the agent's own answer to "could this process install nmap without a
-- privilege escalation?" (root, or the single scoped sudoers entry the installer may create).
-- The hub never assumes it.
ALTER TABLE weirvern.scanner_status
    ADD COLUMN IF NOT EXISTS privileged UInt8 DEFAULT 0,
    ADD COLUMN IF NOT EXISTS scan_mode LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS can_install UInt8 DEFAULT 0,
    -- "root" | "passwordless" | "password" | "none" | "unknown", measured by the agent.
    ADD COLUMN IF NOT EXISTS sudo_state LowCardinality(String) DEFAULT '';
