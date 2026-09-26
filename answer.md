# lab1

## Writing Task 1 (WT1). 
Open trace.pcap with Wireshark. First set filter to eth.src == 6a:15:0a:ba:9b:7c to only reserve Ethernet frames with source address 6a:15:0a:ba:9b:7c. Find the third frame in the filtered results and answer the following questions.
1. How many frames are there in the filtered results? (Hint: see the status bar)

    **Answer:** The number of filtered frames is 827.

2. What is the destination address of this Ethernet frame and what makes this address special?

    **Answer:** The destination MAC address is ff:ff:ff:ff:ff:ff, which is the Ethernet broadcast address. It allows the DHCP Discover message to reach all devices in the local broadcast domain, including any DHCP servers.

3. What is the 71th byte (count from 0) of this frame?

    **Answer:** The byte at offset 71 (counting from 0) is 0x15.

    