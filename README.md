# icmp-tunneling-tool

- date: 2022.10.15

## summary

TCP, UDP 프로토콜이 차단된 내부 망이 있을 때, 내부에서 외부로 ping이 가능한 경우(즉, ICMP 프로토콜이 막히지 않는 경우) 데이터를 유출할 수 있는 ICMP tunneling 기법으로 데이터를 유출시키는 도구.

send.py
- 특정 text 파일을 원하는 IP로 전송

receive.py
- 특정 IP에서 전송하는 ping을 읽어 데이터로 복호화시킴
