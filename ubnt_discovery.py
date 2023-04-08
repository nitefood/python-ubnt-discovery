#!/usr/bin/env python

##########################################
#   UBNT command line discovery tool     #
# Note: this script is very outdated and #
# unmaintained! Leaving this up just for #
# educational purpose, but please look   #
# better and more recent alternatives.   #
##########################################

from random import randint
from scapy.all import *

# UBNT field types
UBNT_MAC         = '01'
UBNT_MAC_AND_IP  = '02'
UBNT_FIRMWARE    = '03'
UBNT_UNKNOWN_2   = '0a'
UBNT_RADIONAME   = '0b'
UBNT_MODEL_SHORT = '0c'
UBNT_ESSID       = '0d'
UBNT_UNKNOWN_3   = '0e'
UBNT_UNKNOWN_1   = '10'
UBNT_MODEL_FULL  = '14'

# UBNT discovery packet payload and reply signature
UBNT_REQUEST_PAYLOAD = '01000000'
UBNT_REPLY_SIGNATURE = '010000'

# Offset within the payload that contains the amount of bytes remaining
offset_PayloadRemainingBytes = 3

# Offset within the payload where we'll find the first field
offset_FirstField = 4

# Discovery timeout. Change this for quicker discovery
DISCOVERY_TIMEOUT = 5


def ubntDiscovery():

    # Prepare and send our discovery packet
    conf.checkIPaddr = False # we're broadcasting our discovery packet from a local IP (local->255.255.255.255)
                             # but we'll expect a reply on the broadcast IP as well (radioIP->255.255.255.255),
                             # not on our local IP.
                             # Therefore we must disable destination IP checking in scapy
    ubnt_discovery_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/\
                            IP(dst="255.255.255.255")/\
                            UDP(sport=randint(1024,65535),dport=10001)/\
                            Raw(UBNT_REQUEST_PAYLOAD.decode('hex'))
    ans, unans = srp(ubnt_discovery_packet,
                     multi=True,    # We want to allow multiple radios to reply to our discovery packet
                     verbose=0,     # Suppress scapy output
                     timeout=DISCOVERY_TIMEOUT)

    # Loop over received packets
    RadioList = {}
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
            elif fieldType == UBNT_ESSID:
                RadioEssid = fieldData
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
        Radio['model_short']    = RadioModelShort

        if RadioIP not in RadioList:
            RadioList[RadioIP] = Radio

    return RadioList


print("\nDiscovery in progress...")
RadioList = ubntDiscovery()
found_radios = len(RadioList)
if found_radios:
    print("\nDiscovered " + str(found_radios) + " radio(s):")
    for Radio in RadioList:
        print("\n--- [" + RadioList[Radio]['model'] + "] ---")
        print("  IP Address  : " + RadioList[Radio]['ip'])
        print("  Name        : " + RadioList[Radio]['name'])
        print("  Model       : " + RadioList[Radio]['model_short'])
        print("  Firmware    : " + RadioList[Radio]['firmware'])
        print("  ESSID       : " + RadioList[Radio]['essid'])
        print("  MAC Address : " + RadioList[Radio]['mac'])
else:
    print("\nNo radios discovered\n")
