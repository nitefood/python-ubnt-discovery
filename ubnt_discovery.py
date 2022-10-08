#!/usr/bin/env python3

##########################################
#   UBNT command line discovery tool     #
# Note: this script is very outdated and #
# unmaintained! Leaving this up just for #
# educational purpose, but please look   #
# better and more recent alternatives.   #
##########################################

import argparse
import json
from random import randint
import struct
import sys

from scapy.all import (
    Ether, IP, UDP, Raw,
    get_if_hwaddr, get_if_list, conf, srp)

def extract_ipv4(mac_and_ip_value):
    """ Extract the Ipv4 from the MAC+IP field

    :return: str dotted representation of the IPv4 (ex: 1.2.3.4)
    """
    ip_part = mac_and_ip_value[6:]
    ip_numbers = struct.unpack('BBBB', ip_part)
    ip_str = '{}.{}.{}.{}'.format(*ip_numbers)
    return ip_str



# UBNT field types
UBNT_MAC         = '01'
UBNT_MAC_AND_IP  = '02'
UBNT_FIRMWARE    = '03'
UBNT_UPTIME      = '0a'
UBNT_RADIONAME   = '0b'
UBNT_MODEL_SHORT = '0c'
UBNT_ESSID       = '0d'
UBNT_WLAN_MODE   = '0e'
UBNT_UNKNOWN_1   = '10'
UBNT_MODEL_FULL  = '14'

# UBNT discovery packet payload and reply signature
UBNT_REQUEST_PAYLOAD = '01000000'
UBNT_REPLY_SIGNATURE = '010000'


# Wirelss modes
UBNT_WIRELESS_MODES ={
    '\x00': "Auto",
    '\x01': "adhoc",
    '\x02': "Station",
    '\x03': "AP",
    '\x04': "Repeater",
    '\x05': "Secondary",
    '\x06': "Monitor",
};

# Offset within the payload that contains the amount of bytes remaining
offset_PayloadRemainingBytes = 3

# Offset within the payload where we'll find the first field
offset_FirstField = 4

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
                            Raw(bytes.fromhex(UBNT_REQUEST_PAYLOAD).decode('utf-8'))
    ans, unans = srp(ubnt_discovery_packet,
                     multi=True,    # We want to allow multiple radios to reply to our discovery packet
                     verbose=0,     # Suppress scapy output
                     timeout=DISCOVERY_TIMEOUT,
                     retry=-3)

    # Loop over received packets
    RadioList = []
    for snd,rcv in ans:

        # We received a broadcast packet in reply to our discovery
        payload = rcv[IP].load

        # Check for a valid UBNT discovery reply (first 3 bytes of the payload should be \x01\x00\x00)
        if bytes.hex(payload[0:3]) == UBNT_REPLY_SIGNATURE:
            Radio = {}          # This should be a valid discovery reply packet sent by an Ubiquiti radio
        else:
            continue            # Not a valid UBNT discovery reply, skip to next received packet

        # Use the received pkt IP in case we hove no better information
        # RadioIP might be overriden by an IP mentioned in the payload.
        RadioIP = rcv[IP].src

        # We avoid going through the hassle of enumerating type '02' fields (MAC+IP). There may
        # be multiple MACs on the radio, and therefore multiple type '02' fields in the
        # reply packet. We conveniently pick the address from which the radio
        # replied to our discovery request directly from the reply packet, and store it.
        RadioMAC = rcv[Ether].src
        RadioMAC = RadioMAC.upper()

        # Retrieve payload size (excluding initial signature)
        pointer = offset_PayloadRemainingBytes
        remaining_bytes = payload[pointer]  # decoded as 8-bit unsigned int by default

        # Walk the reply payload, staring from offset 04 (just after reply signature and payload size).
        pointer += 1
        remaining_bytes -= 1
        while remaining_bytes > 0:
            fieldType = bytes.hex(payload[pointer:pointer+1])
            pointer += 1
            remaining_bytes -= 1
            fieldLen = int.from_bytes(payload[pointer:pointer+2], 'big')  # Data length is stored as a 16-bit word
            pointer += 2
            remaining_bytes -= 2
            fieldData = payload[pointer:pointer+fieldLen]
            if fieldType == UBNT_RADIONAME:
                RadioName = fieldData
            elif fieldType == UBNT_MODEL_FULL:
                RadioModel = fieldData
            elif fieldType == UBNT_MODEL_SHORT:
                RadioModelShort = fieldData
            elif fieldType == UBNT_FIRMWARE:
                RadioFirmware = fieldData
            elif fieldType == UBNT_UPTIME:
                RadioUptime = int.from_bytes(fieldData, 'big')
            elif fieldType == UBNT_ESSID:
                RadioEssid = fieldData
            elif fieldType == UBNT_WLAN_MODE:
                RadioWlanMode = UBNT_WIRELESS_MODES[fieldData.decode()]
            elif fieldType == UBNT_MAC_AND_IP:
                # There might be several IPs
                # Let's use the latest seen that is *not* 169.254.X.X (APIPA)
                ipv4 = extract_ipv4(fieldData)
                if not ipv4.startswith('169.254'):
                    RadioIP = ipv4
            # We don't know or care about other field types. Continue walking the payload.
            pointer += fieldLen
            remaining_bytes -= fieldLen

        # Store the data we gathered from the reply packet
        Radio['ip']             = RadioIP
        Radio['mac']            = RadioMAC
        Radio['name']           = RadioName.decode()
        Radio['model']          = RadioModel.decode()
        Radio['essid']          = RadioEssid.decode()
        Radio['firmware']       = RadioFirmware.decode()
        Radio['uptime']         = RadioUptime
        Radio['model_short']    = RadioModelShort.decode()
        Radio['wlan_mode']      = RadioWlanMode
        RadioList.append(Radio)

    return RadioList


if __name__ == '__main__':
    args = parse_args()
    sys.stderr.write("\nDiscovery in progress...\n")
    RadioList = ubntDiscovery(args.interface)
    found_radios = len(RadioList)
    if args.output_format == 'text':
        if found_radios:
            print("\nDiscovered " + str(found_radios) + " radio(s):")
            for Radio in RadioList:
                print("\n--- [" + Radio['model'] + "] ---")
                print("  IP Address  : " + Radio['ip'])
                print("  Name        : " + Radio['name'])
                print("  Model       : " + Radio['model_short'])
                print("  Firmware    : " + Radio['firmware'])
                print("  ESSID       : " + Radio['essid'])
                print("  MAC Address : " + Radio['mac'])
        else:
            sys.stderr.write("\n\nNo radios discovered\n")
    elif args.output_format == 'json':
        print(json.dumps(RadioList, indent=2))
