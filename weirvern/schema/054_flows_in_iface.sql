-- 054_flows_in_iface.sql
--
-- WHY: a flow could not say WHICH NIC it came through. The tap knows the interface it captured
-- on, but softflowd -- which turns the pcap segment into IPFIX -- cannot report one when it
-- reads a file. Measured on the box four ways (plain, an ingress index, an exporter address and
-- an interface name): the collector recorded in_if=0 and the same sampler address every time.
--
-- So the separation happens where it is a fact rather than a guess: one collector per NIC,
-- all on port 2055, each bound to its own loopback address (127.0.0.1, 127.0.0.2, ...), each
-- writing its own file. The ingester tails every file and stamps the interface the file belongs
-- to into this column. Empty means "not attributed" -- a single-collector deployment, or a
-- record that arrived on the node's LAN address rather than a NIC's loopback.
--
-- ADDITIVE ONLY. Existing rows keep '' and read as unattributed rather than as a guess.
ALTER TABLE weirvern.flows
    ADD COLUMN IF NOT EXISTS in_iface LowCardinality(String) DEFAULT '' AFTER sampler_address;
