import pcapng
import usbmon

with open("/Users/tannewt/Downloads/bad_usb.pcapng", "rb") as f:
    scanner = pcapng.FileScanner(f)
    i = 1
    p = usbmon.Packet()
    for block in scanner:
        if type(block) == pcapng.blocks.EnhancedPacket:
            #print(i, block)
            p.decode(block.packet_payload_info[2])
            if p.transfer_type == 3:
                print(p)
            i += 1
        else:
            print(block)
