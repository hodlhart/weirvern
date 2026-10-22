# Trunk ports are the default sensor topology

Weirvern does not have a "trunk mode". A sensor is wired to a port; the port is either an
access port or an 802.1Q trunk, and the sensor has to work on both without an operator
choosing a mode first.

## What happens on every sensor start

1. The sensor observes its configured capture parent with the same passive observation used
   by Sonar. It records every 802.1Q tag it sees.
2. **No tags:** the state file names the parent (`eth1`). Capture uses `eth1` exactly as before.
3. **Tags:** the sensor creates one host VLAN device per tag (`eth1.10`, `eth1.20`) with
   `ip link add link eth1 name eth1.10 type vlan id 10`, brings each up, and writes those
   names to the capture list. The parent itself is not in the capture list, because its
   tagged frames belong to the VLAN devices.
4. The capture process reads the same state file and starts one Zeek per interface. A VLAN
   device strips the tag on receive, so each VLAN is its own segment with its own address,
   gateway and policy table downstream.
5. If the port is moved back to an access port, the next probe removes the VLAN devices this
   manager created and returns to the parent.

The state is kept on the node (`/var/lib/weirvern/trunk` in Kubernetes, a per-unit directory
on a Docker sensor) so a restart does not forget which devices it owns. A device the manager
did not create is not removed.

## Where the two halves run

- **Kubernetes sensor:** the `trunk-init` container in the Zeek DaemonSet runs the probe
  before the capture container starts. It has `NET_ADMIN` (create/bring up VLAN devices) and
  `NET_RAW` (observe tags).
- **Docker weirling:** `deploy-weirling.sh` runs the same probe in a one-shot worker container
  before starting capture; the agent repeats the probe at startup so its interfaces report
  agrees with the capture list. The agent also carries `NET_ADMIN` for an in-path plan.

A plain trunk port is still not a mirror. The switch must provide a SPAN/mirror that preserves
tags, or the sensor must be genuinely inline. That is a network fact this software cannot
change; the probe reports the tags it can see rather than inventing segments it cannot.

## Limits

- 64 VLANs per port is the manager's cap.
- Native/untagged traffic is not added alongside a tagged VLAN set; the tagged devices are
  the capture list.
- 802.1ad/QinQ is not decoded as two tags; only the outer 802.1Q tag is used.
- Creating devices needs `NET_ADMIN`; a failure is reported in the state and capture falls
  back to the parent visibly.
- VLAN IDs are not security boundaries; the same physical link, CPU and fail-open exposure are
  shared.
