#!/usr/bin/env python3

##########################################
#   UBNT command line discovery tool     #
# Adriano Provvisiero - BV Networks 2016 #
#         www.bvnetworks.it              #
##########################################

import argparse
import json
from random import randint
import sys
from struct import unpack

from scapy.all import (
    Ether, IP, UDP, Raw,
    get_if_hwaddr, get_if_list, conf, srp)

def mac_repr(data):
    return ':'.join(('%02x' % b) for b in data)
def ip_repr(data):
    return '.'.join(('%d' % b) for b in data)

# Wirelss modes
UBNT_WIRELESS_MODES ={
    0x00: "Auto",
    0x01: "adhoc",
    0x02: "Station",
    0x03: "AP",
    0x04: "Repeater",
    0x05: "Secondary",
    0x06: "Monitor",
};

# field type -> (field name; parsing function (bytes->str); \
#                is it expected to be seen multiple times?)
FIELD_PARSERS = {
    0x01: ('mac2', mac_repr, False),
    0x02: ('mac_ip', lambda data: '%s;%s' % (mac_repr(data[0:6]),
                                             ip_repr(data[6:10])), True),
    0x03: ('firmware', bytes.decode, False),
    0x0a: ('uptime', lambda data: int.from_bytes(data, 'big'), False),
    0x0b: ('name', bytes.decode, False),
    0x0c: ('model_short', bytes.decode, False),
    0x0d: ('essid', bytes.decode, False),
    0x0e: ('wlan_mode', lambda data:
               UBNT_WIRELESS_MODES.get(data[0], 'unknown'), False),
    0x10: ('unknown1', str, False),
    0x14: ('model', bytes.decode, False),
}

# Basic fields: src MAC and IP of reply message; not parsed
BASIC_FIELDS = { 'mac', 'ip' }

# String representation of non-basic fields
FIELD_STR = {
    'mac2':     'MAC 2',
    'mac_ip':   'MAC-IP Pairs',
    'firmware': 'Firmware',
    'uptime':   'Uptime',
    'name':     'Name',
    'model_short':  'Model (short)',
    'essid':    'ESSID',
    'wlan_mode':'WLAN Mode',
    'model':    'Model',
}

# UBNT discovery packet payload and reply signature
UBNT_REQUEST_PAYLOAD = b'\x01\x00\x00\x00'
UBNT_REPLY_SIGNATURE = b'\x01\x00\x00'

# Discovery timeout. Change this for quicker discovery
DISCOVERY_TIMEOUT = 5


def parse_args():
    parser = argparse.ArgumentParser(
        description="Discovers ubiquiti devices on network using ubnt device discovery protocol")
    parser.add_argument(
        'interface', help="the interface you want to use for discovery")
    parser.add_argument(
        '--output-format', type=str, default='text', choices=('text', 'json'),
        help="output format")

    return parser.parse_args()

def iter_fields(data, _len):
    pointer = 0
    while pointer < _len:
        fieldType, fieldLen = unpack('>BH', data[pointer:pointer+3])
        pointer += 3
        fieldData = data[pointer:pointer+fieldLen]
        pointer += fieldLen
        yield fieldType, fieldData


def ubntDiscovery(iface):

    if not iface in get_if_list():
        raise ValueError('{} is not a valid network interface'.format(iface))

    src_mac = get_if_hwaddr(iface)

    # Prepare and send our discovery packet
    conf.checkIPaddr = False # we're broadcasting our discovery packet from a local IP (local->255.255.255.255)
                             # but we'll expect a reply on the broadcast IP as well (radioIP->255.255.255.255),
                             # not on our local IP.
                             # Therefore we must disable destination IP checking in scapy
    conf.sniff_promisc=False
    conf.iface = iface
    ubnt_discovery_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)/\
                            IP(dst="255.255.255.255")/\
                            UDP(sport=randint(1024,65535),dport=10001)/\
                            Raw(UBNT_REQUEST_PAYLOAD)
    ans, unans = srp(ubnt_discovery_packet,
                     multi=True,    # We want to allow multiple radios to reply to our discovery packet
                     verbose=0,     # Suppress scapy output
                     timeout=DISCOVERY_TIMEOUT)

    # Loop over received packets
    RadioList = []
    for snd,rcv in ans:

        # We received a broadcast packet in reply to our discovery
        payload = rcv[IP].load

        # Check for a valid UBNT discovery reply (first 3 bytes of the payload should be \x01\x00\x00)
        if payload[0:3] == UBNT_REPLY_SIGNATURE:
            Radio = {}          # This should be a valid discovery reply packet sent by an Ubiquiti radio
        else:
            continue            # Not a valid UBNT discovery reply, skip to next received packet

        Radio['ip'] = \
            rcv[IP].src   # We avoid going through the hassle of enumerating type '02' fields (MAC+IP). There may
                                # be multiple IPs on the radio, and therefore multiple type '02' fields in the
                                # reply packet. We conveniently pick the address from which the radio
                                # replied to our discovery request directly from the reply packet, and store it.

        Radio['mac'] = rcv[Ether].src.upper() # Read comment above, this time regarding the MAC Address.

        # Walk the reply payload, staring from offset 04 (just after reply signature and payload size).
        # Take into account the payload length in offset 3
        for fieldType, fieldData in iter_fields(payload[4:], payload[3]):

            if fieldType not in FIELD_PARSERS:
                sys.stderr.write("notice: unknown field type 0x%x: data %s\n" %
                                 (fieldType, fieldData))
                continue

            # Parse the field and store in Radio
            fieldName, fieldParser, isMany = FIELD_PARSERS[fieldType]
            if isMany:
                if fieldName not in Radio: Radio[fieldName] = []
                Radio[fieldName].append(fieldParser(fieldData))
            else:
                Radio[fieldName] = fieldParser(fieldData)

        # Store the data we gathered from the reply packet
        RadioList.append(Radio)

    return RadioList

if __name__ == '__main__':
    args = parse_args()
    sys.stderr.write("\nDiscovery in progress...\n")
    RadioList = ubntDiscovery(args.interface)
    found_radios = len(RadioList)
    if args.output_format == 'text':
        if not found_radios:
            sys.stderr.write("\n\nNo radios discovered\n")
            sys.exit()
        print("\nDiscovered %d radio(s):" % found_radios)
        fmt = "  %-14s: %s"
        for Radio in RadioList:
            print("\n---[ %s ]---" % Radio['mac'])
            print(fmt % ("IP Address", Radio['ip']))
            for field in Radio:
                if field in BASIC_FIELDS: continue
                print(fmt % (FIELD_STR.get(field, field),
                             Radio[field]))
    elif args.output_format == 'json':
        print(json.dumps(RadioList, indent=2))
