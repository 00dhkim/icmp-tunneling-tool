import pyshark
from pprint import pprint

#TODO: sudo tcpdump -w packet/{datetime}.pcap -i eth0 icmp src 0.0.0.0

captured = pyshark.FileCapture('packet/kor.pcapng')

packet_list = []

for packet in captured:
    try:
        if packet.icmp.type == '0': # Echo (ping) reply
            pass
        elif packet.icmp.type == '8':
            received_data = bytes.fromhex(packet.icmp.data) # hex string -> bytes
            filename, id_, content_length, datafield = received_data.split(b'\x1f') # unit separator
            packet_list.append({
                'id': int(id_),
                'filename': filename.decode('utf-8'),
                'content_length': int(content_length),
                'datafield': datafield # bytes
            })
        if packet.icmp.type == '0':
            print(f'[+] {packet.number} ping')
        elif packet.icmp.type == '8':
            print(f'[+] {packet.number} pong')
        else:
            print(f'[+] {packet.number} type:{packet.icmp.type}')
    except AttributeError: # not icmp packet
        pass
    except Exception as e:
        print(f'[-] {e}')

packet_list = sorted(packet_list, key=lambda x: (x['filename'], x['id']))

# print(len(packet_list))
# pprint(packet_list)
