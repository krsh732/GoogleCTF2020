import angr
import sys
import claripy

def basic_symbolic_execution():
    p = angr.Project('a.out')
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(16)]
    state = p.factory.entry_state(stdin=claripy.Concat(*flag_chars))
    for c in flag_chars[:-1]:
        state.solver.add(c >= 0x20)
        state.solver.add(c < 0x7f)
    state.solver.add(flag_chars[-1] == ord('\n'))
    sm = p.factory.simulation_manager(state)
    sm.run()
    for x in sm.deadended:
        if b"SUCCESS" in x.posix.dumps(1):
            return x.posix.dumps(0)


if __name__ == '__main__':
    sys.stdout.buffer.write(basic_symbolic_execution())