#!/usr/bin/env python

import pcapng
import pcapng.blocks as blocks
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('outfile', type=argparse.FileType('wb'))
args = parser.parse_args()

shb = blocks.SectionHeader(options={
    'shb_hardware':'artificial',
    'shb_os':'python',
    'shb_userappl':'python-pcapng'
    })
shb.write(args.outfile)
idb = shb.new_member(blocks.InterfaceDescription, link_type=1,
        options={"if_description": "Hand-rolled", "if_os": "Python"})
idb.write(args.outfile)


test_pl = (
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, # dest MAC
        0x11, 0x22, 0x33, 0xdd, 0xaa, 0x00, # src MAC
        0x08, 0x00,                         # ethertype (ipv4)
        0x45, 0x00, 0x00, 31,               # IP start
        0x00, 0x00, 0x00, 0x00,             # ID+flags
        0xfe, 17,                           # TTL, UDP
        0x00, 0x00,                         # checksum
        127, 0, 0, 1,                       # src IP
        127, 0, 0, 2,                       # dst IP
        0x12, 0x34, 0x56, 0x78,             # src/dst ports
        0x00, 11,                           # length
        0x00, 0x00,                         # checksum
        0x44, 0x41, 0x50,                   # Payload
)

spb = shb.new_member(blocks.SimplePacket)
spb.packet_data = bytes(test_pl)
spb.write(args.outfile)
