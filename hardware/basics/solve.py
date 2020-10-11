from pwn import remote

class PtrHack:
    def __init__(self):
        self.value = None

def rtl_concat(*args):
    return [i for l in args[::-1] for i in l]

def solve_check(target_num):
    memory = [[PtrHack() for j in range(7)] for i in range(8)]
    magic = rtl_concat(
        rtl_concat(memory[0], memory[5]),
        rtl_concat(memory[6], memory[2]),
        rtl_concat(memory[4], memory[3]),
        rtl_concat(memory[7], memory[1])
    )
    kittens = rtl_concat(magic[0:10], magic[22:42], magic[10:22], magic[42:56])
    for i, p in enumerate(kittens):
        p.value = (target_num >> i) & 1

    s = ""
    for i in range(len(memory)):
        s += chr(sum(p.value*2**j for j, p in enumerate(memory[(5*i) & 7])))
    return s


if __name__ == "__main__":
    password = solve_check(3008192072309708)
    print(f"Password: {password}")
    io = remote("basics.2020.ctfcompetition.com", 1337)
    io.sendlineafter("Enter password:\n", password)
    io.interactive()