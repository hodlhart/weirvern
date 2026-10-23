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
4. **`zeek-conn` — observed, not guessed.** A matching `zeek_conn` row names the originating
   endpoint; a 5-tuple match in either orientation upgrades this flow to request or reply.
5. **`service-port` — inferred, not proven.** One endpoint is a service port and the other is
   not. The service side is the responder. This is what correctly labels the normal HTTPS and
   DNS halves, including the common case where the exporter lost the handshake.
6. **`unknown` — no claim.** Neither handshake nor a service-port shape. Two ephemeral peers,
   a cumulative flags byte, or an ICMP flow land here. The table says `unknown`; it does not
   reverse a row to make the picture look tidy.

The **opened by** field names the initiator only when the role lets us name it (the source of
a request, or the destination of a reply). For `unknown`, it says `not proven`.

The table also carries a small **arrow** for the roles that are evidenced: `→ request` means
this record's source opened, and `← reply` means it answered. `· unknown` deliberately has no
arrow, because a direction invented from a guess is the defect this column exists to prevent.

## Zeek conn.log enrichment

The flow exporter does not put an originator in a unidirectional record. Zeek does: every
`conn.log` row names the originating endpoint (`id.orig_h` / `id.orig_p`) and the responder.
The Flows page joins its page of flow rows to `zeek_conn` on the exact 5-tuple in either
orientation, within a bounded time distance, and uses the nearest match. A matching row upgrades
the flow to `zeek-conn` evidence, which outranks the service-port inference. A missing or
ambiguous match leaves the existing evidence unchanged; the join is an enhancement, never a
page failure.

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

- **Remote Zeek shipping** would extend the `zeek-conn` join to sensors whose capture is not on
  the hub's own host. The local capture is covered today; remote shipping is not implemented.
- **A biflow exporter** that emits `flowDirection` plus both byte counters would let the
  collector pair halves at export time. The current exporter emits unidirectional records.

## The Network map's orientation

The Network map uses the SAME service-port predicate as Flows and Discover
(`soc._is_service_port`: system ports plus a curated service list). It does not use a second
boundary. The old graph code treated every port below 32768 as a service; IANA's ranges are
**system 0–1023, user 1024–49151, dynamic/private 49152–65535**, and 32768 is merely the usual
Linux ephemeral start. A user port such as 35623 therefore could not prove a request.

A **one-sided reply** is observed as `server:service -> client:ephemeral`. The graph now orients
that edge `client -> server`, puts the service port on the destination card and the client's
source port on the source card. The detail says the request was not captured; it is still not a
request/reply pair, and the map does not pretend otherwise. A one-sided request keeps the
observed `client -> server`; an edge whose two ports prove neither shape keeps a neutral
`direction not claimed`.

When neither port is in the curated service table, the graph may use the **client-port shape**
as a weaker inference: all destination ports ≥32768 and all source ports <32768 is a reply
shape (and the reverse is a request shape). This is named `ephemeral-shape` in the edge
evidence, never `service-port`, because 32768 is the usual Linux client start rather than an
IANA service boundary. It is what keeps NNTP on 5563 or Bitcoin on 8333 from becoming unknown
merely because those ports are not in the curated table.

The host-pair aggregate still limits how finely multiple services between the same two hosts can
be separated; the 5-tuple is present in the raw records and is the next step when the graph query
is grouped by it.

## Where the code lives

- `weirvern/admin/soc.py`: `_flow_direction`, `_tcp_role`, `_port_role`,
  `_reverse_direction_flags`, `_zeek_direction_roles`.
- `weirvern/admin/web/discover.js`: direction cell with its arrow, row detail, evidence tooltip.
- `tests/test_discover.py`: proof, inference, reverse-half, Zeek-conn and unknown cases.
