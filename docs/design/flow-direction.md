# Flow direction: proof, inference, and the honest unknown

The Flows tab lists **unidirectional flow records**, not conversations. A record is one
direction of one 5-tuple as the exporter observed it. When a host opens an outbound HTTPS
connection, the request and the reply arrive as two separate rows:

```
198.51.100.20:51515 -> 203.0.113.10:443    request
203.0.113.10:443    -> 198.51.100.20:51515 reply
```

Both rows are correct packet directions. The second one is not "backwards"; it is the reply
half. Showing it without a label made the reader reverse the conversation mentally. The
Flows table now carries a **direction** column and the row detail carries the evidence.

## The evidence ladder

The server classifies every row in this order. A weaker source is never allowed to override a
stronger one.

1. **`tcp-syn` — proven.** This record carries a bare SYN (TCP flags exactly `0x02`). Its
   source opened the conversation.
2. **`tcp-syn-ack` — proven.** This record carries a bare SYN-ACK (`0x12`). Its source answered
   a conversation opened by the other side.
3. **`reverse-tcp-syn` / `reverse-tcp-syn-ack` — proven by the other half.** This row has no
   handshake itself, but its reverse 5-tuple in the same window does. A reverse bare SYN makes
   this row the reply; a reverse bare SYN-ACK makes it the request.
4. **`service-port` — inferred, not proven.** One endpoint is a service port and the other is
   not. The service side is the responder. This is what correctly labels the normal HTTPS and
   DNS halves, including the common case where the exporter lost the handshake.
5. **`unknown` — no claim.** Neither handshake nor a service-port shape. Two ephemeral peers,
   a cumulative flags byte, or an ICMP flow land here. The table says `unknown`; it does not
   reverse a row to make the picture look tidy.

The **opened by** field names the initiator only when the role lets us name it (the source of
a request, or the destination of a reply). For `unknown`, it says `not proven`.

## Why cumulative TCP flags are not proof

`tcp_flags` in a flow record is a bitwise OR of every packet in that record, not the flags of
its first packet. A perfectly ordinary request flow often carries `SYN+ACK+PSH+FIN` (`27`)
because later packets set ACK and PSH. Treating any SYN+ACK bit pattern as a handshake would
turn that request into a reply. Only the exact bare values `2` and `18` are used as direct
handshake evidence; everything else falls through to the reverse-half check or the port
inference.

## Why IPFIX `flowDirection` is not "who opened it"

IPFIX field 61 (`flowDirection`) describes whether the exporter observed the packet on an
ingress or egress interface. It is a fact about the **observation point**, not about the
client/server role. A reply can be ingress or egress depending on where the exporter sits.
The current exporter does not populate it either. It is deliberately not used as a synonym
for request/reply.

## What would make it stronger

- **Zeek `conn.log`** carries `orig_h`/`orig_p` and `resp_h`/`resp_p`; Zeek establishes the
  originator from the TCP handshake (or first packet for UDP). Joining a flow to its Zeek
  connection would upgrade many `service-port` rows to provenance from Zeek. Remote Zeek
  shipping is not implemented yet, so this is a future enrichment, not a current claim.
- **A biflow exporter** that emits `flowDirection` plus both byte counters would let the
  collector pair halves at export time. The current exporter emits unidirectional records.

## Where the code lives

- `weirvern/admin/soc.py`: `_flow_direction`, `_tcp_role`, `_port_role`,
  `_reverse_direction_flags`.
- `weirvern/admin/web/discover.js`: direction cell, row detail, evidence tooltip.
- `tests/test_discover.py`: proof, inference, reverse-half and unknown cases.
