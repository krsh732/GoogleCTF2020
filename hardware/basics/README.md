# Basics

**Problem Description:**

> With all those CPU bugs I don't trust software anymore, so I came up  with my custom TPM (trademark will be filed soon!). You can't break  this, so don't even try.<br>
>
> [Attachment](./3da8bc17f534eec284ee0f7f0cb473218365fc189dec41931240c2a7dcd0fcea4968cd56561525e184a0043efaff7a5029bb581afbc6ce89491b8384db6d8b1a)<br>
>
> `basics.2020.ctfcompetition.com 1337`

## Solution

The attachment contained three files:

- [.keep](./keep)
- [check.sv](./check.sv)
- [main.cpp](./main.cpp)

`.keep` was pretty much useless, as it was a 0 byte file. That left me with only `check.sv` and `main.cpp` to look at.

**TODO:** stop being lazy and write some words instead.

### solve.py

```python
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
```

### Flag

```bash
$ python3 solve.py
Password: 7LoX%*_x
[+] Opening connection to basics.2020.ctfcompetition.com on port 1337: Done
[*] Switching to interactive mode
CTF{W4sTh4tASan1tyCh3ck?}
```

### main.cpp

```cpp
#include "obj_dir/Vcheck.h"

#include <iostream>
#include <memory>

int main(int argc, char *argv[]) {
    Verilated::commandArgs(argc, argv);
    std::cout << "Enter password:" << std::endl;
    auto check = std::make_unique<Vcheck>();

    for (int i = 0; i < 100 && !check->open_safe; i++) {
        int c = fgetc(stdin);
        if (c == '\n' || c < 0) break;
        check->data = c & 0x7f;
        check->clk = false;
        check->eval();
        check->clk = true;
        check->eval();
    }
    if (check->open_safe) {
        std::cout << "CTF{real flag would be here}" << std::endl;
    } else {
        std::cout << "=(" << std::endl;
    }
    return 0;
}
```

### check.sv

```verilog
module check(
    input clk,

    input [6:0] data,
    output wire open_safe
);

reg [6:0] memory [7:0];
reg [2:0] idx = 0;

wire [55:0] magic = {
    {memory[0], memory[5]},
    {memory[6], memory[2]},
    {memory[4], memory[3]},
    {memory[7], memory[1]}
};

wire [55:0] kittens = { magic[9:0],  magic[41:22], magic[21:10], magic[55:42] };
assign open_safe = kittens == 56'd3008192072309708;

always_ff @(posedge clk) begin
    memory[idx] <= data;
    idx <= idx + 5;
end

endmodule
```