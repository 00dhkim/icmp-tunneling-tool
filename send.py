import pyping

# r = pyping.ping('example.com')
# print(r.ret_code)

text = '''lorem ipsum dolor sit amet, consectetur adipiscing elit.
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
ut enim ad minim veniam, quis nostrud exercitation ullamco laboris
nisi ut aliquip ex ea commodo consequat. duis aute irure dolor in
reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
pariatur. excepteur sint occaecat cupidatat non proident, sunt in
culpa qui officia deserunt mollit anim id est laborum.'''*10


# no return
pyping.icmp_tunnel(hostname='loopback', text=text, count=1, encrypt=False)
