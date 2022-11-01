import pyshark
from pprint import pprint

# capture with pyshark
captured = pyshark.FileCapture('packet/two_file.pcapng')

# TODO: data decryption if needed
# \x1f로 split 안된다 -> 복호화 시도
# 복호화 실패 -> error

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
        if packet.icmp.type == '8':
            print(f'[+] {packet.number} ping')
        elif packet.icmp.type == '0':
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

# get all filename in packet_list
filenames = sorted(list(set([x['filename'] for x in packet_list])))
# print(filenames)

for filename in filenames:
    # get all packet with same filename
    same_filename = [x for x in packet_list if x['filename'] == filename]
    # print(len(same_filename))
    # print(same_filename)
    # print(same_filename[0]['content_length'])
    # print(len(same_filename[0]['datafield']))
    # print(same_filename[0]['datafield'])
    
    # get all datafield
    datafield_list = [x['datafield'] for x in same_filename]
    # print(len(datafield_list))
    # print(datafield_list)
    
    # join all datafield
    data = b''.join(datafield_list)
    # print(len(data))
    # print(data)
    
    # verify content_length
    if same_filename[0]['content_length'] != len(data):
        print(f'[-] {filename} content_length error')
        continue
    else:
        print(f'[+] {filename} content_length ok')
    
    # save file
    with open(filename, 'wb') as f:
        f.write(data)
