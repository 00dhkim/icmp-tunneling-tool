# icmp-tunneling-tool

- date: 2022.10.15

## summary

TCP, UDP 프로토콜이 차단된 내부 망이 있을 때, 내부에서 외부로 ping이 가능한 경우(즉, ICMP 프로토콜이 막히지 않는 경우) 데이터를 유출할 수 있는 ICMP tunneling 기법으로 데이터를 유출시키는 도구.

send.py
- 원하는 IP 지정
- binary 파일 전송
    - metadata(filename, content length, id) 함께 보내야 함
    - filename: 실제 파일 명
    - content length: 파일의 길이
    - id: 파일을 분할할 때, 패킷의 고유번호 (0, 1, 2, ...)
- 데이터 암호화 지원
    - AES-CBC 대칭키 암호화

receive.py
- 특정 IP에서 전송하는 ping을 읽어 데이터로 복호화시킴
