# pcap_grabber

A simple command line utility to obtain pcap files from an ExtraHop System.

## Instructions

1. Download either the mac or windows executable file (or compile yourself)
2. Have a 'keys' file (that matches the format of the key file shown in this repo) in the same directory as the executable
3. Run the executable
4. The program will ask you to enter a name for a session.. feel free to use any string here (no spaces)
5. You will be asked to either capture all packets going to a single IP address... or to capture all packets sent between two IP addresses
6. Once you make your selection, enter either the one or both IP addresses you desire to get packets from.
7. Wait for the packet captures to show up (they will begin showing as connections complete to your desired IP addresses)
8. Once you've had enough.. press 1 to download all the pcaps to your system.
9. ** If you have Wireshark installed on your machine.. the script will attempt to use libraries provided by Wireshark into 1 single, large pcap.  If Wireshark is not installed.. this will it will notify you it could not find Wireshark.  This is completely optional
