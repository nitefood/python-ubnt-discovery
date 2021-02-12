# python-ubnt-discovery
Command line python script to discover Ubiquiti devices on the local LAN segment.

**Requirements :** the script uses the python scapy library to craft and send the raw packet. You can install it with:

`pip install scapy`

####Ubiquiti Discovery Protocol brief description

*Disclaimer: there are some fields that remain unknown. This code may therefore not be compatible with all devices.*

There are multiple methods of the Ubiquiti discovery protocol.

Method 1 works by sending an UDP packet to the local broadcast address (255.255.255.255) on port **10001**,
containing 4 bytes in the payload, namely `01 00 00 00`, and waiting for UDP replies destined to the local
broadcast address.

Method 2 works by periodacly sending an UDP packet to the local broadcast address (255.255.255.255) on port **10001**. 

Method 3 is multicast on the address 233.89.188.1.

The payload of the reply packet sent by the radio is structured as follows:
- offset `00` (3 bytes) : *Ubiquiti discovery reply signature the first byte is the version. Depending on the version the field definitions change.*
- offset `03` (1 byte) : *Payload size (excluding signature)*

Starting at offset `04`, the structure of the payload is as follows:
- `Field Type`        (1 byte) : *see the UBNT_ constants in the code for the ones I saw and could figure out*
- `Field data length` (2 bytes) : *contains the length of this field's data*
- `Field data`        (*n* bytes) : *contains the actual field data (eg. radio name, firmware version, etc)*

This sequence is repeated for every field in the reply packet.

In case the radio has multiple IPs configured, we'll get several type *02* fields (MAC Address + IP Address).

The other field types appear only once in the packets I have observed.
