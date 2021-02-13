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
from scapy.all import *

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
# These are validated
    0x01: ('HWADDR', mac_repr, False),
    0x02: ('IPINFO', lambda data: '%s;%s' % (mac_repr(data[0:6]), ip_repr(data[6:10])), True),
    0x03: ('FWVERSION', bytes.decode, False),
    0x0a: ('UPTIME', lambda data: int.from_bytes(data, 'big'), False),
    0x0b: ('HOSTNAME', bytes.decode, False),
    0x0c: ('PLATFORM', bytes.decode, False),
    0x0d: ('ESSID', bytes.decode, False),
    0x0e: ('WMODE', lambda data: UBNT_WIRELESS_MODES.get(data[0], 'unknown'), False),
    0x10: ('SYSTEM_ID', lambda data: int.from_bytes(data, 'big'), False),
    0x12: ('SEQ', lambda data: int.from_bytes(data, 'big'), False),
    0x13: ('SRC_MACID', mac_repr, False),
    0x15: ('MODEL', bytes.decode, False),
    0x16: ('VERSION', bytes.decode, False),
    0x17: ('MGMT_IS_DEFAULT', lambda data: int.from_bytes(data, 'big'), False),
    0x19: ('MGMT_USING_DHCPC', lambda data: int.from_bytes(data, 'big'), False),
    0x1a: ('MGMT_DHCPC_BOUND', lambda data: int.from_bytes(data, 'big'), False),
    0x1b: ('REQUIRED_VERSION', bytes.decode, False),
    0x1c: ('SSHD_PORT', lambda data: int.from_bytes(data, 'big'), False),
    0x1e: ('TALK_ANONYMOUS_DEVICE_ID', bytes.decode, False),
# These need checking
    0x04: ('ADDR_ENTRY', str, False),
    0x05: ('MAC_ENTRY', str, False),
    0x06: ('USERNAME', str, False),
    0x07: ('SALT', str, False),
    0x08: ('RND_CHALLENGE', str, False),
    0x09: ('CHALLENGE_RESPONSE', str, False),
    0x0f: ('MGMT_URL', str, False),
    0x11: ('MGMT_LOCATE_SECONDS', str, False),
    0x1d: ('PLATFORM_UVP', str, False),
# Same for these, it might be that it is v1 vs v2
    0x14: ('model', bytes.decode, False),
    0x14: ('DST_MACID', str, False),
    0x18: ('default_config', lambda data: int.from_bytes(data, 'big'), False),
    0x18: ('MGMT_IS_LOCATING', lambda data: int.from_bytes(data, 'big'), False),
# These need names
    0x0f: ('unknown1 (unifi-os related?)', lambda data: int.from_bytes(data, 'big'), False),
    0x21: ('unknown2', str, False),
    0x22: ('unknown3', str, False),
    0x24: ('unknown4 TS?', lambda data: int.from_bytes(data, 'big'), False),
    0x27: ('unknown5', str, False),
    0x2a: ('unknown6', str, False),
    0x2d: ('unknown7 (led related?)', lambda data: int.from_bytes(data, 'big'), False),
    0x2e: ('unknown8 (led related?)', str, False),
}

FIELD_PARSERS_V1 = {
    0x14: ('model', bytes.decode, False),
    0x18: ('default_config', lambda data: int.from_bytes(data, 'big'), False),
}

FIELD_PARSERS_V2 = {
    0x14: ('DST_MACID', str, False),
    0x18: ('MGMT_IS_LOCATING', lambda data: int.from_bytes(data, 'big'), False),
}

# Basic fields: src MAC and IP of reply message; not parsed
BASIC_FIELDS = { 'mac', 'ip' }

# String representation of non-basic fields
FIELD_STR = {
    'HWADDR':     'HWADDR',
#    'HWADDR':     'MAC (Serial)',
#    'mac3':     'MAC 3',
#    'IPINFO':   'MAC-IP Pairs',
#    'FWVERSION': 'Firmware',
#    'firmware_short': 'Firmware (short)',
#    'uptime':   'Uptime',
#    'name':     'Hostname',
#    'model_short':  'Model (short)',
#    'essid':    'ESSID',
#    'wlan_mode':'WLAN Mode',
#    'model':    'Model',
#    'default_config':    'Default configuration',
}

# UBNT discovery packet payload and reply signature
UBNT_REQUEST_PAYLOAD = b'\x01\x00\x00\x00'
UBNT_V1_SIGNATURE = b'\x01\x00\x00'
UBNT_V2_SIGNATURE = b'\x02\x06\x00'

# Discovery timeout. Change this for quicker discovery
DISCOVERY_TIMEOUT_ACTIVE = 2
DISCOVERY_TIMEOUT_PASSIVE = 10

def parse_args():
    parser = argparse.ArgumentParser(
        description="Discovers ubiquiti devices on network using ubnt device discovery protocol")
    parser.add_argument(
        '--interface', type=str, help="the interface you want to use for discovery")
    parser.add_argument(
        '--pcap', type=str, help="analyze a pcap file for discovery info")
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

def ubntResponseParse(rcv):
    # We received a broadcast packet in reply to our discovery
    payload = rcv.load

    if payload[0:4] == UBNT_REQUEST_PAYLOAD: # Check for a UBNT discovery request (first 4 bytes of the payload should be \x01\x00\x00\x00)
        return False
    elif payload[0:3] == UBNT_V1_SIGNATURE: # Check for a valid UBNT discovery reply (first 3 bytes of the payload should be \x01\x00\x00)
        Device = {}          # This should be a valid discovery reply packet sent by an Ubiquiti device
        Device['Signature version'] = '1' # this is not allways correct
    elif payload[0:3] == UBNT_V2_SIGNATURE:
        Device = {}          # This should be a valid discovery broadcast packet sent by an Ubiquiti device
        Device['Signature version'] = '2'
    else:
        return False            # Not a valid UBNT discovery reply, skip to next received packet

    Device['mac'] = rcv[Ether].src.upper() # Read comment above, this time regarding the MAC Address.

    # Walk the reply payload, staring from offset 04 (just after reply signature and payload size).
    # Take into account the payload length in offset 3
    for fieldType, fieldData in iter_fields(payload[4:], payload[3]):

        if fieldType not in FIELD_PARSERS:
            sys.stderr.write("notice: unknown field type 0x%x: data %s\n" %
                             (fieldType, fieldData))
            continue

        # Parse the field and store in Device
        fieldName, fieldParser, isMany = FIELD_PARSERS[fieldType]
        if isMany:
            if fieldName not in Device: Device[fieldName] = []
            Device[fieldName].append(fieldParser(fieldData))
        else:
            Device[fieldName] = fieldParser(fieldData)

    return Device

def ubntDiscovery(args):

    DeviceList = []

    if args.pcap is not None:

        packets = rdpcap(args.pcap)

        for packet in packets:

            if UDP in packet:

                if packet[UDP].dport == 10001 or packet[UDP].sport == 10001:

                    device = ubntResponseParse(packet)

                    print(device)
                    if device != False:
                        DeviceList.append(device)

    if args.interface is not None:

        iface = args.interface

        if not args.interface in get_if_list():
            raise ValueError('{} is not a valid network interface'.format(iface))

        src_mac = get_if_hwaddr(args.interface)

        # Prepare and send our discovery packet
        conf.checkIPaddr = False # we're broadcasting our discovery packet from a local IP (local->255.255.255.255)
                             # but we'll expect a reply on the broadcast IP as well (deviceIP->255.255.255.255),
                             # not on our local IP.
                             # Therefore we must disable destination IP checking in scapy
        conf.iface = args.interface
        ubnt_discovery_packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)/\
                                IP(dst="255.255.255.255")/\
                                UDP(sport=randint(1024,65535),dport=10001)/\
                                Raw(UBNT_REQUEST_PAYLOAD)

        # do active discovery first, after it we do passive discovery

        ans, unans = srp(ubnt_discovery_packet,
                     multi=True,    # We want to allow multiple radios to reply to our discovery packet
                     verbose=0,     # Suppress scapy output
                     timeout=DISCOVERY_TIMEOUT_ACTIVE)

        wrpcap('active.pcap', ans)

        for snd,rcv in ans:

            # Store the data we gathered from the reply packet
            device = ubntResponseParse(rcv)
            if device != False:
                DeviceList.append(device)


        # passive discovery

        packets = sniff(filter='dst port 10001', timeout=DISCOVERY_TIMEOUT_PASSIVE)

        wrpcap('passive.pcap', packets)

        # Loop over received packets
        for rcv in packets:

            # Store the data we gathered from the reply packet
            device = ubntResponseParse(rcv)
            if device != False:
                DeviceList.append(device)

    return DeviceList

if __name__ == '__main__':
    args = parse_args()
    sys.stderr.write("\nDiscovery in progress...\n")
    DeviceList = ubntDiscovery(args)
    found_devices = len(DeviceList)
    if args.output_format == 'text':
        if not found_devices:
            sys.stderr.write("\n\nNo devices discovered\n")
            sys.exit()
        print("\nDiscovered %d device(s):" % found_devices)
        fmt = "  %-30s: %s"
        for Device in DeviceList:
            print("\n---[ %s ]---" % Device['mac'])
            for field in Device:
                if field in BASIC_FIELDS: continue
                print(fmt % (FIELD_STR.get(field, field),
                             Device[field]))
    elif args.output_format == 'json':
        print(json.dumps(DeviceList, indent=2))
