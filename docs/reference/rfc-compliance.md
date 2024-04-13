# RFC-compliance

-   ✅ Compliant
-   ❓ Not applicable or not compliant to a MAY
-   ⚠️ Not compliant to a SHOULD or RECOMMENDED
-   ❌ Not compliant to a MUST

If there is no ❌ for a RFC then it compliant to the RFC, and if there is also no ⚠️ for the RFC then it fully-compliant to the RFC.

## RFC 4787

https://datatracker.ietf.org/doc/html/rfc4787#section-12

Compliant except [REQ-14](#req-14), receiving out-of-order fragments.

### REQ-1

-   A NAT MUST have an "Endpoint-Independent Mapping" behavior
-   ✅ Compliant.

### REQ-2

-   It is RECOMMENDED that a NAT have an "IP address pooling"
    behavior of "Paired". Note that this requirement is not
    applicable to NATs that do not support IP address pooling.
-   ❓ Not applicable.

`einat` does support "IP address pooling" so this requirement is not applicable.

However, with `bpf_fib_lookup_external` enabled `einat` would query routing table to determine initial NAT external address which is similar to "IP address pooling". And if there is some policy-based routing rule(i.e. `ip rule`) selects preferred external address that is destination dependent, the "Paired" behavior would be broken.

### REQ-3

-   A NAT MUST NOT have a "Port assignment" behavior of "Port
    overloading"
-   ✅ Compliant.

`einat` just drops the packet if there is no free ports for assignment.

**REQ-3a**

-   If the host's source port was in the range 0-1023, it is
    RECOMMENDED the NAT's source port be in the same range. If the
    host's source port was in the range 1024-65535, it is
    RECOMMENDED that the NAT's source port be in that range.
-   ⚠️ Not compliant.

`einat` would try preserving the original port number if possible and then do sequential port assignment.

### REQ-4

-   It is RECOMMENDED that a NAT have a "Port parity
    preservation" behavior of "Yes".
-   ⚠️ Not compliant.

### REQ-5

-   A NAT UDP mapping timer MUST NOT expire in less than two
    minutes, unless REQ-5a applies.
-   ✅ Compliant in default configuration.

**REQ-5a**

-   For specific destination ports in the well-known port range
    (ports 0-1023), a NAT MAY have shorter UDP mapping timers that
    are specific to the IANA-registered application running over
    that specific destination port.
-   ❓ Not Compliant.

**REQ-5b**

-   The value of the NAT UDP mapping timer MAY be configurable.
-   ✅ Compliant.

**REQ-5c**

-   A default value of five minutes or more for the NAT UDP mapping
    timer is RECOMMENDED.
-   ⚠️ Not compliant.

We default the UDP timeout to 5 minutes only for traffic seen packets from both inbound and outbound direction.

### REQ-6

-   The NAT mapping Refresh Direction MUST have a "NAT Outbound
    refresh behavior" of "True".
-   ✅ Compliant.

**REQ-6a**

-   The NAT mapping Refresh Direction MAY have a "NAT Inbound
    refresh behavior" of "True".
-   ❓ Not compliant.

`einat` only allows inbound refreshing for ICMP query packets.

### REQ-7

-   A NAT device whose external IP interface can be configured
    dynamically MUST either (1) Automatically ensure that its internal
    network uses IP addresses that do not conflict with its external
    network, or (2) Be able to translate and forward traffic between
    all internal nodes and all external nodes whose IP addresses
    numerically conflict with the internal network.
-   ✅ Compliant with proper network configuration.

### REQ-8

-   If application transparency is most important, it is
    RECOMMENDED that a NAT have "Endpoint-Independent Filtering"
    behavior. If a more stringent filtering behavior is most
    important, it is RECOMMENDED that a NAT have "Address-Dependent
    Filtering" behavior.
-   ✅ Compliant.

### REQ-9

-   A NAT MUST support "Hairpinning".
-   ✅ Compliant with proper `einat` configuration.

**REQ-9a**

-   A NAT Hairpinning behavior MUST be "External source IP address
    and port".
-   ✅ Compliant.

### REQ-10

-   To eliminate interference with UNSAF NAT traversal
    mechanisms and allow integrity protection of UDP communications,
    NAT ALGs for UDP-based protocols SHOULD be turned off. Future
    standards track specifications that define an ALG can update this
    to recommend the ALGs on which they define default.
-   ❓ Not applicable, `einat` does not have NAT ALGs.

**REQ-10a**

-   If a NAT includes ALGs, it is RECOMMENDED that the NAT allow
    the NAT administrator to enable or disable each ALG separately
-   ❓ Not applicable.

### REQ-11

-   A NAT MUST have deterministic behavior, i.e., it MUST NOT
    change the NAT translation (Section 4) or the Filtering
    (Section 5) Behavior at any point in time, or under any particular
    conditions.
-   ✅ Compliant.

### REQ-12

-   Receipt of any sort of ICMP message MUST NOT terminate the
    NAT mapping.
-   ✅ Compliant.

**REQ-12a**

-   The NAT's default configuration SHOULD NOT filter ICMP messages
    based on their source IP address.
-   ✅ Compliant.

`einat` replace IP source address with destination address in embedded error IP packet and filter by it instead.

**REQ-12b**

-   It is RECOMMENDED that a NAT support ICMP Destination
    Unreachable messages.
-   ✅ Compliant.

### REQ-13

-   If the packet received on an internal IP address has DF=1,
    the NAT MUST send back an ICMP message "Fragmentation needed and
    DF set" to the host, as described in [RFC0792].
-   ✅ Compliant, the Linux kernel or network interface should guarantees this.

**REQ-13a**

-   If the packet has DF=0, the NAT MUST fragment the packet and
    SHOULD send the fragments in order.
-   ✅ Compliant, the Linux kernel or network interface should guarantees this.

`einat` just filters and NAT the packet and does not changes the packet size so this is not `einat`'s responsibility to handle fragmentation.

### REQ-14

-   A NAT MUST support receiving in-order and out-of-order
    fragments, so it MUST have "Received Fragment Out of Order"
    behavior.
-   ❌ Not compliant.

**REQ-14a**

-   A NAT's out-of-order fragment processing mechanism MUST be
    designed so that fragmentation-based DoS attacks do not
    compromise the NAT's ability to process in-order and
    unfragmented IP packets.
-   ❌ Not compliant.

`einat` only does fragments tracking without reassemble the full packet.
So if the first fragment received is not the first fragment("More Fragments"=1 and offset=0) containing layer 4 header in sequence, previously received out-of-order fragments can not be forwarded to NATed destination.

## RFC 5508

https://datatracker.ietf.org/doc/html/rfc5508#section-9

Compliant.

### REQ-1

-   Unless explicitly overridden by local policy, a NAT device
    MUST permit ICMP Queries and their associated responses, when
    the Query is initiated from a private host to the external
    hosts.
-   ✅ Compliant.

**REQ-1a**

-   NAT mapping of ICMP Query Identifiers SHOULD be external
    host independent.
-   ✅ Compliant.

### REQ-2

-   An ICMP Query session timer MUST NOT expire in less than 60
    seconds.
-   ✅ Compliant.

**REQ-1a**

-   It is RECOMMENDED that the ICMP Query session timer be made
    configurable.
-   ✅ Compliant.

Currently we use the same timeout value for UDP and ICMP.

### REQ-3

-   When an ICMP Error packet is received, if the ICMP checksum
    fails to validate, the NAT SHOULD silently drop the ICMP Error
    packet. If the ICMP checksum is valid, do the following:
-   ✅ Compliant.

For "REQ-3","REQ-3a" and "REQ-3c", `einat` does not validate checksum of any types of packet, however the kernel or network interface should guarantees that.

**REQ-3a**

-   If the IP checksum of the embedded packet fails to
    validate, the NAT SHOULD silently drop the Error packet;
    and
-   ✅ Compliant.

**REQ-3b**

-   If the embedded packet includes IP options, the NAT device
    MUST traverse past the IP options to locate the start of
    the transport header for the embedded packet; and
-   ✅ Compliant.

**REQ-3c**

-   The NAT device SHOULD NOT validate the transport checksum
    of the embedded packet within an ICMP Error message, even
    when it is possible to do so; and
-   ✅ Compliant.

**REQ-3d**

-   If the ICMP Error payload contains ICMP extensions
    [ICMP-EXT], the NAT device MUST exclude the optional zero-
    padding and the ICMP extensions when evaluating transport
    checksum for the embedded packet.
-   ❓ Not applicable.

`einat` does not handles ICMP extensions, it only parses the first ICMP extension as traditional ICMP Error packet.

### REQ-4

-   If a NAT device receives an ICMP Error packet from an external
    realm, and the NAT device does not have an active mapping for
    the embedded payload, the NAT SHOULD silently drop the ICMP
    Error packet. If the NAT has active mapping for the embedded
    payload, then the NAT MUST do the following prior to
    forwarding the packet, unless explicitly overridden by local
    policy:
-   a) Revert the IP and transport headers of the embedded IP
    packet to their original form, using the matching mapping;
    and
-   b) Leave the ICMP Error type and code unchanged; and
-   c) Modify the destination IP address of the outer IP header to
    be same as the source IP address of the embedded packet
    after translation.
-   ✅ Compliant.

### REQ-5

-   If a NAT device receives an ICMP Error packet from the private
    realm, and the NAT does not have an active mapping for the
    embedded payload, the NAT SHOULD silently drop the ICMP Error
    packet. If the NAT has active mapping for the embedded
    payload, then the NAT MUST do the following prior to
    forwarding the packet, unless explicitly overridden by local
    policy.
-   (a) Revert the IP and transport headers of the embedded IP
    packet to their original form, using the matching mapping;
    and
-   (b) Leave the ICMP Error type and code unchanged; and
-   ✅ Compliant.

**REQ-5c**

-   (c) If the NAT enforces Basic NAT function [NAT-TRAD], and the
    NAT has active mapping for the IP address that sent the
    ICMP Error, translate the source IP address of the ICMP
    Error packet with the public IP address in the mapping. In
    all other cases, translate the source IP address of the
    ICMP Error packet with its own public IP address.
-   ✅ Compliant with a single external address.

`einat` always replace IP source address with destination address in embedded error IP packet and use the mapping of it instead.

So if `bpf_fib_lookup_external` is enabled and the external address of "the intermediate node" is different from external address of "destination address in embedded error IP packet", this requirement no longer compliant.

See also [RFC 4787, REQ-2](#req-2).

### REQ-6

-   While processing an ICMP Error packet pertaining to an ICMP
    Query or Query response message, a NAT device MUST NOT refresh
    or delete the NAT Session that pertains to the embedded
    payload within the ICMP Error packet.
-   ✅ Compliant.

### REQ-7

-   NAT devices enforcing Basic NAT ([NAT-TRAD]) MUST support the
    traversal of hairpinned ICMP Query sessions. All NAT devices
    (i.e., Basic NAT as well as NAPT devices) MUST support the
    traversal of hairpinned ICMP Error messages.
-   ✅ Compliant.

**REQ-7a**

-   When forwarding a hairpinned ICMP Error message, the NAT
    device MUST translate the destination IP address of the
    outer IP header to be same as the source IP address of the
    embedded IP packet after the translation.
-   ✅ Compliant.

`einat` only allows packet with the same destination IP address of the outer IP header and source IP address of the
embedded IP packet, thus the address after the translation would also be the same.

### REQ-8

-   When a NAT device is unable to establish a NAT Session for a
    new transport-layer (TCP, UDP, ICMP, etc.) flow due to
    resource constraints or administrative restrictions, the NAT
    device SHOULD send an ICMP destination unreachable message,
    with a code of 13 (Communication administratively prohibited)
    to the sender, and drop the original packet.
-   ⚠️ Not compliant.

Tracked in https://github.com/EHfive/einat-ebpf/issues/8.

### REQ-9

-   A NAT device MAY implement a policy control that prevents ICMP
    messages being generated toward certain interface(s).
    Implementation of such a policy control overrides the MUSTs
    and SHOULDs in REQ-10.
-   ❓ Not applicable.

### REQ-10

-   Unless overridden by REQ-9's policy, a NAT device needs to
    support ICMP messages as below, some conforming to Section
    4.3 of [RFC1812] and some superseding the requirements of
    Section 4.3 of [RFC1812]: ... (see original RFC for details)

See [section 7](https://datatracker.ietf.org/doc/html/rfc5508#section-7) for sub-requirement descriptions.

**REQ-10a**

-   ✅ Compliant.

**REQ-10b**

-   ❓ Not compliant.

Only "Timestamp and Timestamp Reply Messages" and "Parameter Problem Message" are supported in `einat`.

**REQ-10c**

-   ✅ Compliant.

**REQ-10d, REQ-10e, REQ-10f**

-   ❓ Not compliant or ✅ compliant with kernel support.

### REQ-11

-   A NAT MAY drop or appropriately handle Non-QueryError ICMP
    messages. The semantics of Non-QueryError ICMP messages is
    defined in Section 2.
-   ❓ Not compliant or ✅ compliant with kernel support.

## RFC 5382

https://datatracker.ietf.org/doc/html/rfc5382#section-8

Fully compliant.

### REQ-1

-   A NAT MUST have an "Endpoint-Independent Mapping" behavior
    for TCP.
-   ✅ Compliant.

### REQ-2

-   A NAT MUST support all valid sequences of TCP packets
    (defined in [RFC0793]) for connections initiated both internally
    as well as externally when the connection is permitted by the NAT.
    In particular:
-   (a) In addition to handling the TCP 3-way handshake mode of
    connection initiation, A NAT MUST handle the TCP simultaneous-
    open mode of connection initiation.
-   ✅ Compliant.

### REQ-3

-   If application transparency is most important, it is
    RECOMMENDED that a NAT have an "Endpoint-Independent Filtering"
    behavior for TCP. If a more stringent filtering behavior is most
    important, it is RECOMMENDED that a NAT have an "Address-Dependent
    Filtering" behavior.
-   ✅ Compliant.

**REQ-3a**

-   The filtering behavior MAY be an option configurable by the
    administrator of the NAT.
-   ❓ Not applicable.

**REQ-3b**

-   The filtering behavior for TCP MAY be independent of the
    filtering behavior for UDP.
-   ❓ Not applicable.

`einat` has only "Endpoint-Independent Filtering" behavior for any supported protocols.

### REQ-4

-   A NAT MUST NOT respond to an unsolicited inbound SYN packet
    for at least 6 seconds after the packet is received. If during
    this interval the NAT receives and translates an outbound SYN for
    the connection the NAT MUST silently drop the original unsolicited
    inbound SYN packet.
-   ✅ Compliant.

**REQ-4a**

-   Otherwise, the NAT SHOULD send an ICMP Port
    Unreachable error (Type 3, Code 3) for the original SYN, unless
    REQ-4a applies.
-   The NAT MUST silently drop the original SYN packet if sending a
    response violates the security policy of the NAT.
-   ✅ Compliant if we seen the security policy as applied.

`einat` drops unsolicited inbound SYN packet by default.

### REQ-5

-   If a NAT cannot determine whether the endpoints of a TCP
    connection are active, it MAY abandon the session if it has been
    idle for some time. In such cases, the value of the "established
    connection idle-timeout" MUST NOT be less than 2 hours 4 minutes.
    The value of the "transitory connection idle-timeout" MUST NOT be
    less than 4 minutes.
-   (a) The value of the NAT idle-timeouts MAY be configurable.
-   ✅ Compliant.

### REQ-6

-   If a NAT includes ALGs that affect TCP, it is RECOMMENDED
    that all of those ALGs (except for FTP [RFC0959]) be disabled by
    default.
-   ❓ Not applicable.

Same as [RFC 4787, REQ-10](#req-10).

### REQ-7

-   A NAT MUST NOT have a "Port assignment" behavior of "Port
    overloading" for TCP.
-   ✅ Compliant.

### REQ-8

-   A NAT MUST support "hairpinning" for TCP.
-   ✅ Compliant.

### REQ-9

-   If a NAT translates TCP, it SHOULD translate ICMP Destination
    Unreachable (Type 3) messages.
-   ✅ Compliant.

### REQ-10

-   Receipt of any sort of ICMP message MUST NOT terminate the
    NAT mapping or TCP connection for which the ICMP was generated.
-   ✅ Compliant.

## RFC 7857

https://datatracker.ietf.org/doc/html/rfc7857

Compliant.

### TCP Session Tracking

-   The TCP state machine depicted in Figure 1, adapted from
    [RFC6146], SHOULD be implemented by a NAT for TCP session tracking
    purposes.
-   ✅ Compliant.

### TCP Transitory Connection Idle-Timeout

-   This document clarifies that a NAT SHOULD provide
    different configurable parameters for configuring the open and
    closing idle timeouts
-   ⚠️ Not compliant.

-   To accommodate deployments that consider a partially open timeout
    of 4 minutes as being excessive from a security standpoint, a NAT
    MAY allow the configured timeout to be less than 4 minutes.
    However, a minimum default transitory connection idle-timeout of 4
    minutes is RECOMMENDED.
-   ✅ Compliant.

### TCP RST

-   Concretely, when the NAT receives a TCP RST matching
    an existing mapping, it MUST translate the packet according to the
    NAT mapping entry. Moreover, the NAT SHOULD wait for 4 minutes
    before deleting the session and removing any state associated with
    it if no packets are received during that 4-minute timeout.
-   ✅ Compliant.

### Port Overlapping Behavior

-   If destination addresses and ports are different for outgoing
    connections started by local clients, a NAT MAY assign the same
    external port as the source ports for the connections.
-   ❓ Not applicable as `einat` has EIM behavior.

### Address Pooling Paired

-   ❓ Not applicable.

Same as [RFC 4787, REQ-2](#req-2)

### EIM Protocol Independence

-   ❓ Not applicable.

`einat` has "Endpoint-Independent Mapping" behavior for any supported protocols.

### EIF Protocol Independence

-   ❓ Not applicable.

`einat` has "Endpoint-Independent Filtering" behavior for any supported protocols.

### EIF Mapping Refresh

-   ❓ Not applicable.

### Outbound Mapping Refresh and Error Packets

-   In the case of NAT outbound refresh behavior, ICMP Errors or
    TCP RST outbound packets sent as a response to inbound packets
    SHOULD NOT refresh the mapping.
-   ✅ Compliant.

### Port Parity

-   ❓ Not compliant.

### Port Randomization

-   ❓ Not applicable.

`einat` would try preserving the original port number if possible and then do sequential port assignment.

### IP Identification

-   A NAT SHOULD handle the Identification field of translated
    IPv4 packets as specified in [Section 5.3.1 of RFC6864](https://datatracker.ietf.org/doc/html/rfc6864#section-5.3.1).
-   ✅ Compliant.

`einat` uses source address, destination address, layer 4 protocol number, interface index and direction in addition to IP ID to distinguish between fragmentation sessions.

### ICMP Query Mappings Timeout

-   ICMP Query mappings MAY be deleted once the last session
    using the mapping is deleted.
-   ✅ Compliant as this is the default for any protocols in `einat`.

[ICMP-EXT]: https://datatracker.ietf.org/doc/html/rfc4884
[NAT-TRAD]: https://datatracker.ietf.org/doc/html/rfc3022
[RFC1812]: https://datatracker.ietf.org/doc/html/rfc1812
[RFC0793]: https://datatracker.ietf.org/doc/html/rfc0793
