#!/usr/bin/env python3
"""Parse and print details of DJI Duml packets

Usage:

    python3 dumlparser.py 550D04332A2835124000002AE4

"""

import sys
import dumlcrc as crc
import dumlutils as utils


def isdumlvalid(packet):
    if len(packet) < 13 or len(packet) > 0x01FF:
        print("Packet length of", len(packet), "is invalid")
        return False

    if packet[0] != 0x55:
        print("Invalid duml magic ", packet[0])
        return False

    if len(packet) != (packet[1] | ((packet[2] & 0x03) <<8)):
        print("Invalided encoded packet length")
        return False

    if packet[3] != crc.calc_crc8([packet[0],packet[1],packet[2]]):
        print("Header CRC8 is invalid")
        return False

    trimPacket = []
    for i in range(len(packet) - 2):
        trimPacket.append(packet[i])

    crc16a = utils.bytes_to_int([packet[len(packet)-1],packet[len(packet)-2]])
    crc16b = crc.calc_crc16(trimPacket)

    if crc16a != crc16b:
        print("Packet CRC32 is invalid")
        return False

    return True


def parse(packet):

    print("Length\t\t", packet[1] | ((packet[2] & 0x03) << 8))
    print("Version\t\t", packet[2] >> 2)
    print("CRC8\t\t", utils.bytes_to_int([packet[len(packet)-1], packet[len(packet)-2]]))

    print("\nSrc\t\t\t", packet[4] >> 5)
    print("SrcID\t\t", packet[4] & 0x0E)
    print("Dest\t\t", packet[5] >> 5)
    print("DestID\t\t", packet[5] & 0x0E)
    print("Counter\t\t", ((packet[7] & 0xFF) << 8) | packet[6] & 0xFF)

    print("\ncmdType\t\t", packet[8] & ~0x1F)  # ToDo encryption bit is encoded here #ToDo print as hex
    print("cmdSet\t\t", packet[9])  # ToDo print as hex
    print("cmdID\t\t", packet[10])  # ToDo print as hex

    if len(packet) > 13:
        bytearray = []
        for b in range(11, len(packet) - 2):
            bytearray.append(packet[b])
        print("\nPayload\t\t", bytearray)

    print("\nCRC16\t\t", utils.bytes_to_int([packet[len(packet)-1], packet[len(packet)-2]]))


def main(hexstr):
    packet = bytes.fromhex(hexstr)

    if not isdumlvalid(packet):
        print("Invalid duml packet")
    parse(packet)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("python3 dumlparser.py 550D04332A2835124000002AE4")
    else:
        main(sys.argv[1])
