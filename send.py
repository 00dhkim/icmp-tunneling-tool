import pyping

# r = pyping.ping('example.com')
# print(r.ret_code)

r = pyping.icmp_tunnel('example.com', 'this is a contents')
print(r.ret_code)