import pcapng
import csv
import io
from pcapng.structs import IntField, PacketDataField, OptionsField, Options

import usbmon
import sys

def output_urb(timestamp, urb, outstream):
    packet = pcapng.blocks.EnhancedPacket(None, header)
    packet.interface_id = 0
    packet.packet_payload_info = ()
    packet.timestamp_high = (timestamp >> 32) & 0xffffffff
    packet.timestamp_low = timestamp & 0xffffffff
    raw_urb = urb.encode()
    packet.packet_payload_info = (len(raw_urb), len(raw_urb), raw_urb)
    packet.options = Options(packet.schema[4][1].options_schema, {}, "<")

    # if urb.setup_flag != 0:
    #     print(urb)

    packet.encode(outstream)

filename = sys.argv[1]
noextension = filename.rsplit(".", 1)[0]

with open(filename, "r") as file_in:
    with open(noextension + ".pcapng", "wb") as out:
        csvreader = csv.reader(file_in)
        header = None
        data = bytearray()
        urb = usbmon.Packet()
        setup_complete = False
        for row in csvreader:
            if len(row) > 4 and "packet" in row[-4]:
                packet_type = row[-4].strip()
                timestamp = row[3]
                #print(row[2], row[3], row[4], row[-6], row[-5], packet_type, row[-3])

                if packet_type == "SETUP packet":
                    urb.event_type = ord('S')
                    pid, addr, endp = row[-3].split()
                    urb.device_address = int(addr, 16)
                    urb.endpoint_number = int(endp, 16)
                    urb.transfer_type = 2 # control
                    urb.setup_flag = 0
                    setup_complete = False
                elif packet_type == "IN packet":
                    if urb.setup_flag != 0:
                        if not urb.event_type:
                            urb.event_type = ord('S')
                        urb.transfer_type = 3 # bulk
                        pid, addr, endp = row[-3].split()
                        urb.device_address = int(addr, 16)
                        urb.endpoint_number = int(endp[::-1], 16)
                    elif urb.union.bmRequestType == 0:
                        setup_complete = True
                elif packet_type == "OUT packet":
                    if urb.setup_flag != 0:
                        urb.event_type = ord('S')
                        urb.transfer_type = 3 # bulk
                        pid, addr, endp = row[-3].split()
                        urb.device_address = int(addr, 16)
                        urb.endpoint_number = int(endp[::-1], 16)
                    elif urb.union.bmRequestType != 0:
                        setup_complete = True
                elif packet_type.startswith("DATA"):
                    packet_data = bytearray()
                    for b in row[-3].split()[1:]:
                        packet_data.append(int(b, 16))
                    if urb.setup_flag == 0 and len(packet_data) == 10 and urb.event_type == ord('S'):
                        setup_data = usbmon.SetupData()
                        setup_data.decode(packet_data[:9])
                        urb.union = setup_data
                    else:
                        data.extend(packet_data[:-2])
                elif packet_type == "ACK packet":
                    packet = pcapng.blocks.EnhancedPacket(None, header)
                    packet.interface_id = 0
                    packet.packet_payload_info = ()
                    urb.data = bytes(data)
                    min_sec, msec, usec = timestamp.split(".")
                    mins, secs = min_sec.split(":")
                    seconds = 60 * int(mins) + int(secs)
                    microseconds = 1000 * int(msec) + int(usec)
                    urb.ts_sec = seconds
                    urb.ts_usec = microseconds
                    total_microseconds = seconds * 1000000 + microseconds
                    if urb.setup_flag == 0:
                        if urb.event_type == ord('S'):
                            output_urb(total_microseconds, urb, out)
                            urb.event_type = ord('C')
                        elif not setup_complete:
                            pass
                        else:
                            output_urb(total_microseconds, urb, out)
                            data = bytearray()
                            urb = usbmon.Packet()
                    # MSC packets start with USB so this is a crude way to group them like Linux does.
                    elif urb.data[:3] == b"USB":
                        output_urb(total_microseconds, urb, out)
                        data = bytearray()
                        urb.event_type = ord('C')
                    else:
                        output_urb(total_microseconds, urb, out)
                        data = bytearray()
                        urb = usbmon.Packet()
                elif packet_type == "STALL packet":
                    data = bytearray()
                    urb = usbmon.Packet()
                elif packet_type == "NAK packet":
                    # Data is retransmitted so drop it.
                    data = bytearray()
                else:
                    raise RuntimeError("unsupported packet type {}".format(packet_type))
            if row[0] == "# Level":
                header = pcapng.blocks.SectionHeader()
                header.version_major = 1
                header.version_minor = 0
                header.section_length = -1
                header.options = Options(header.schema[3][1].options_schema, {}, "<")
                header.encode(out)
                interface = pcapng.blocks.InterfaceDescription(b'', header)
                interface.link_type=220
                interface.reserved = b''
                interface.snaplen = 0xffffffff
                interface.options = Options(interface.schema[3][1].options_schema, {}, "<")
                interface.encode(out)
