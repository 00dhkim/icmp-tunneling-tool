import pyshark
from pprint import pprint
import encryptor

captured = pyshark.FileCapture('packet/packet_enc_1101.pcapng')
# captured = pyshark.FileCapture('packet/two_file.pcapng')


def is_encrypted(data: bytes):
    """
    received_data가 암호화되었는지 판단하는 함수\n
    split 했을 때 결과가 4이고, id_의 길이가 8 byte이면 평문으로 판단
    """
    if len(data.split(b'\x1f')) != 4:
        return True
    if len(data.split(b'\x1f')[1]) != 8:
        return True
    return False


packet_list = []

#############################################
# 패킷을 하나씩 읽어서 packet_list에 저장
#############################################

for packet in captured:
    try:
        if packet.icmp.type == '0': # Echo (ping) reply aka. pong
            print(f'[+] No.{packet.number} Echo reply. skipped.')
        elif packet.icmp.type == '8': # Echo (ping) request
            print(f'[+] No.{packet.number} Echo request')
            received_data = bytes.fromhex(packet.icmp.data) # hex string -> bytes
            
            # 암호화 여부 판단
            isEncrypted = is_encrypted(received_data)
            print(f'    [+] Encrypted: {isEncrypted}')
            
            if isEncrypted:
                received_data = encryptor.decrypt(received_data) # 복호화
            
            filename, id_, content_length, datafield = received_data.split(b'\x1f') # unit separator
            packet_list.append({
                'id': int(id_),
                'filename': filename.decode('utf-8'),
                'content_length': int(content_length),
                'datafield': datafield # bytes
            })
        else:
            print(f'[+] No.{packet.number} type:{packet.icmp.type}. skipped.')
    except AttributeError: # not icmp packet
        pass
    except Exception as e:
        print(f'[-] {e} at line {e.__traceback__.tb_lineno}')

packet_list = sorted(packet_list, key=lambda x: (x['filename'], x['id']))
# print(len(packet_list))
# pprint(packet_list)


#############################################
# packet_list를 순회하면서 파일을 생성
#############################################

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
