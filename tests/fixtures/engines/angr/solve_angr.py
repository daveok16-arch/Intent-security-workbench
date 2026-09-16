import sys
import angr
import claripy

def main():
    binary_path = 'tests/fixtures/engines/angr/test_crackme'
    proj = angr.Project(binary_path, auto_load_libs=False)

    # Symbolic input for argv[1] of 4 bytes
    arg1 = claripy.BVS('arg1', 4 * 8)
    state = proj.factory.entry_state(args=[binary_path, arg1])

    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=lambda s: b"SUCCESS" in s.posix.dumps(1))

    if simgr.found:
        solution_state = simgr.found[0]
        solved_input = solution_state.solver.eval(arg1, cast_to=bytes)
        print("ANGR_STATUS: SUCCESS")
        print(f"FOUND_INPUT: {solved_input}")
        print(f"STATES_EXPLORED: {len(simgr.deadended) + len(simgr.found)}")
        print(f"TERMINATION: TARGET_FOUND")
        return 0
    else:
        print("ANGR_STATUS: NOT_FOUND")
        return 1

if __name__ == '__main__':
    sys.exit(main())
