# lab2

## Writing Task 2 (WT2). 
Open trace.pcap with Wireshark. Answerthe following questions.
1. During an ARP interaction, which field in ARP Reply is the same as the Sender MAC address in ARP Request?

    **Answer:** Target MAC address 

2. How many IPv4 packets are there whose Don’t fragment bit is not set?

    **Answer:** 6

3. What are the header lengths of IPv4 and IPv6 packets respectively (not including IP options)?

    **Answer:** 
    - IPv4: 20 bytes
    - IPv6: 40 bytes

## Writing Task 3 (WT3).
sendFrame() requires the caller to provide the destination MAC address when sending IP packets, but users of IP layer will not provide the address to you. Explain how you addressed this problem when implementing IP protocol.

**Answer:** The application supplies source/destination IP addresses, protocol, and payload to `sendIPPacket()`. It does not supply an Ethernet destination. The IP layer calls `findRouter()` with the destination IP, selects the longest matching valid route, and obtains the outgoing interface and next-hop MAC from that route.

The route obtains its MAC in either of the following ways:

1. **Manual routing:** `setRoutingTable()` explicitly receives a next-hop MAC and interface. CP3 uses this interface to configure a host route before sending.
2. **Dynamic routing:** `handleDV()` records the source MAC of the received Ethernet advertisement and its receiving interface. That neighbor is the next hop for routes learned from the advertisement. CP4 and CP5 therefore learn both the route and the link-layer address needed to use it.

`sendIPPacket()` copies the selected MAC and calls `sendFrame()` with EtherType `0x0800`. For a remote destination, this MAC belongs to the immediate neighbor, while the IPv4 destination remains the final host. Each forwarding router selects its own next-hop MAC and constructs a new Ethernet header.

The source also contains an ARP fallback for a route with an all-zero MAC: it searches the ARP cache for the route's next-hop IP and, on a miss, sends requests and retries. This branch requires a meaningful next-hop IP and an active receiver to process replies. The public manual-route API supplies a MAC, and DV learns a MAC directly; the recorded checkpoints use these two paths and do not depend on an ARP exchange. The ARP fallback is not described as the default path for these experiments.

## Writing Task 4 (WT4).
Describe your routing algorithm.

**Answer:** Our routing algorithm is based on the **Distance Vector (DV) algorithm**, which uses hop count as the routing metric and follows the distributed Bellman-Ford algorithm. A metric of 16 represents an unreachable destination. Routing updates are broadcast in Ethernet frames with EtherType `0x88B6`, containing the destination prefix, subnet mask, and hop count.

The algorithm consists of three main components:

1. **Initialization and Broadcasting:** Each interface's local IP address is initialized as a `/32` route with a metric of 0. An initial routing update is broadcast immediately after startup. Subsequently, `sendDV()` is called approximately every second on each interface to advertise the current distance vector.

2. **Receiving and Updating Routes:** Upon receiving a routing advertisement, `handleDV()` validates the message and adds 1 to the advertised metric, capped at 16. Routes are matched by destination prefix and subnet mask. A new route replaces an existing route if it has a lower metric. If an update comes from the current next hop, the route is updated even if its metric increases or becomes unreachable. When metrics are equal, the existing next hop is preserved. Manually configured and local routes cannot be overwritten by dynamic routing updates.

3. **Timeout and Garbage Collection:** If a dynamic route receives no accepted reachable update for 5 consecutive seconds, it is marked as unreachable. The route is retained for another 5 seconds to advertise its withdrawal before being deleted. Repeated unreachable advertisements do not reset the garbage-collection timer. During this period, the route can be restored if an acceptable reachable advertisement is received.

**Poison Reverse** is implemented to reduce routing loops. When advertising routes through an interface, dynamically learned routes whose next hop is reachable through that interface are advertised with a metric of 16, without modifying the actual routing table. Local and manually configured routes are not subject to poison reverse.

For packet forwarding, **Longest Prefix Matching (LPM)** is used to select the most specific matching route. Hop count is used only to compare alternative paths to the same destination prefix.

**Boundary Conditions:** The routing table supports up to 64 entries, and the maximum reachable distance is 15 hops. Malformed routing advertisements are discarded. When the routing table is full, new routes are not added, but existing routes can still be updated. For each destination prefix, only the currently selected route is maintained; alternative routes advertised by other neighbors are not stored.
