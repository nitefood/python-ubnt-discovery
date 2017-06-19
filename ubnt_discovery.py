#!/usr/bin/env python

##########################################
#   UBNT command line discovery tool     #
# Adriano Provvisiero - BV Networks 2016 #
#         www.bvnetworks.it              #
##########################################

import argparse
import json
from random import randint

from scapy.all import (
    Ether, IP, UDP, Raw,
    get_if_hwaddr, get_if_list, conf, srp)


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
                            Raw(UBNT_REQUEST_PAYLOAD.decode('hex'))
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
        if payload[0:3].encode('hex') == UBNT_REPLY_SIGNATURE:
            Radio = {}          # This should be a valid discovery reply packet sent by an Ubiquiti radio
        else:
            continue            # Not a valid UBNT discovery reply, skip to next received packet

        RadioIP = rcv[IP].src   # We avoid going through the hassle of enumerating type '02' fields (MAC+IP). There may
                                # be multiple IPs on the radio, and therefore multiple type '02' fields in the
                                # reply packet. We conveniently pick the address from which the radio
                                # replied to our discovery request directly from the reply packet, and store it.

        RadioMAC = rcv[Ether].src # Read comment above, this time regarding the MAC Address.
        RadioMAC = RadioMAC.upper()

        # Retrieve payload size (excluding initial signature)
        pointer = offset_PayloadRemainingBytes
        remaining_bytes = int( payload[pointer].encode('hex'), 16 )

        # Walk the reply payload, staring from offset 04 (just after reply signature and payload size).
        pointer += 1
        remaining_bytes -= 1
        while remaining_bytes > 0:
            fieldType = payload[pointer].encode('hex')
            pointer += 1
            remaining_bytes -= 1
            fieldLen = payload[pointer:pointer+2].encode('hex') # Data length is stored as a 16-bit word
            fieldLen = int( fieldLen, 16 )
            pointer += 2
            remaining_bytes -= 2
            fieldData = payload[pointer:pointer+fieldLen]
            if  fieldType == UBNT_RADIONAME:
                RadioName = fieldData
            elif fieldType == UBNT_MODEL_FULL:
                RadioModel = fieldData
            elif fieldType == UBNT_MODEL_SHORT:
                RadioModelShort = fieldData
            elif fieldType == UBNT_FIRMWARE:
                RadioFirmware = fieldData
            elif fieldType == UBNT_UPTIME:
                RadioUptime = int(fieldData.encode('hex'), 16)
            elif fieldType == UBNT_ESSID:
                RadioEssid = fieldData
            elif fieldType == UBNT_WLAN_MODE:
                RadioWlanMode = UBNT_WIRELESS_MODES[fieldData]
            # We don't know or care about other field types. Continue walking the payload.
            pointer += fieldLen
            remaining_bytes -= fieldLen

        # Store the data we gathered from the reply packet
        Radio['ip']             = RadioIP
        Radio['mac']            = RadioMAC
        Radio['name']           = RadioName
        Radio['model']          = RadioModel
        Radio['essid']          = RadioEssid
        Radio['firmware']       = RadioFirmware
        Radio['uptime']         = RadioUptime
        Radio['model_short']    = RadioModelShort
        Radio['wlan_mode']      = RadioWlanMode
        RadioList.append(Radio)

    return RadioList


if __name__ == '__main__':
    args = parse_args()
    print("\nDiscovery in progress...")
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
            print("\nNo radios discovered\n")
    elif args.output_format == 'json':
        print(json.dumps(RadioList, indent=2))
