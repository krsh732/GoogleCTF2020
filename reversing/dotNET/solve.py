import sys
from z3 import *   

BitVecRef.__lt__ = ULT
BitVecRef.__le__ = ULE
BitVecRef.__gt__ = UGT
BitVecRef.__ge__ = UGE
BitVecRef.__truediv__ = UDiv
BitVecRef.__mod__ = URem
BitVecRef.__rshift__ = LShR

s = Solver()
MATHOPEN = [BitVec(f'{i}', 32) for i in range(30)]
for var in MATHOPEN:
	s.add(var >= 0, var < 64)

# SMORBALL
num = BitVecVal(16, 32)
for i in range(len(MATHOPEN)):
    if i == len(MATHOPEN) - 2:
        continue
    num += MATHOPEN[i]
    if i % 2 == 0:
        num += MATHOPEN[i]
    if i % 3 == 0:
        num += MATHOPEN[i] * 4294967294
    if i % 5 == 0:
        num += MATHOPEN[i] * 4294967293
    if i % 7 == 0:
        num += MATHOPEN[i] * 4
s.add(MATHOPEN[-2] == (num & 63))

# HEROISK
## VAXMYRA
for i in range(0, len(MATHOPEN)):
    for j in range(0, i):
        s.add(MATHOPEN[i] != MATHOPEN[j])

## rest of HEROISK 
with open('rest_of_heroisk.cs', 'r') as f:
    rest_of_heroisk = f.read()

nuke_list = ["(uint)","uint ", "(int)", "int ", "U", ";"]
for i in nuke_list:
    rest_of_heroisk = rest_of_heroisk.replace(i, "")
rest_of_heroisk = rest_of_heroisk.splitlines()

op_swaps = [(" ? ", ")) #"), (" > ", " <= "), (" >= ", " < "), (" < ", " >= "),
            (" <= ", " > "), (" != ", " == "), (" == ", " != ")]

for i in rest_of_heroisk:
    if "{" in i or "}" in i or "return" in i:
        continue
    
    line = i
    if "if" in i:
        for op in op_swaps:
            line = line.replace(op[0], op[1])
            if line != i:
                break
        line = line.replace("if ", "s.add")
    exec(line.lstrip().rstrip())

if s.check() != sat:
	print("NO HOPE")
	sys.exit(1)

model = s.model()
shuffled_answer = [model[MATHOPEN[i]].as_long() for i in range(len(MATHOPEN))]
shuffle_map = [2, 12, 4, 0, 21, 22, 11, 15, 23, 27, 5, 10, 6, 19, 20, 9, 16, 
                24, 8, 1, 7, 26, 17, 25, 3, 13, 18, 14, 28, 29]
answer = [0]*len(shuffled_answer)
for i,c in enumerate(shuffle_map):
    answer[c] = shuffled_answer[i]
alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}"
for i, c in enumerate(b"\x1F\x23\x3F\x3F\x1B\x07\x37\x21\x04\x33\x09\x3B\x39\x28\x30\x0C\x0E\x2E\x3F\x25\x2A\x27\x3E\x0B\x27\x1C\x38\x31\x1E\x3D"):
    answer[i] ^= c
    answer[i] = alphabet[answer[i]]
print(''.join(answer))
