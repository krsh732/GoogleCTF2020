# .NET

**Problem Description:**

> .NET is great, especially because of all its weird features.<br>
>
> [Attachment](./a8d65cb3b53a09c557b4e9a1744e08f73d0571dba9d79241fed3519cdd38f14c51472b108353f033e3223b5ec48bb8f0296b2abc3142ea0690592b9904816d3b)

## Solution

Upon running `EKTORPFlagValidator.exe` we are greeted with the following window:

<center><img src="./images/EKTORPFlagValidator.png"/></center>

Since I had no clue what the flag was, I demanded it give me the flag instead. To which, as you can see, it told me to try again :cry:.

##  TODO

Unfortunately this write-up is severely lacking at the moment. In the meantime, the solve script can be found [here](./solve.py), though I'm not sure if any of it will make any sense by itself. 

Write a lot more meaningful words perhaps? For example:

- About harmony and how it was used to hook some functions
- About how some of the flag logic was actually unmanaged native code
- Talk about pretty much everything really...

## Flag

```
$ python3 solve.py
CTF{CppClrIsWeirdButReallyFun}
```

