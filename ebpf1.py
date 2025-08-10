#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = """

BPF_HASH(clones);



int hello_world(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = clones.lookup(&uid);
    if ( p != 0) {
        counter = *p;
    }

    counter++;
    clones.update(&uid, &counter);

    return 0;
}
"""

b = BPF(text=program, cflags=["-Wno-macro-redefined"])
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello_world")

print("Tracing clone syscalls... ")

# b.trace_print()

try:
    while True:
        sleep(2)
        s = ""
        if len(b["clones"].items()):
            for k, v in  b["clones"].items():
                s += "ID {}: {}\t".format(k.value, v.value)
            print(s)
        else:
            print("No entries yet")
except KeyboardInterrupt:
    print("\nDetaching and exiting.")

#try:
#    while True:
#        line = b.trace_readline()
#        if line:
#            print(line.decode('utf-8', errors='replace'), end='\n', flush=True)
#except KeyboardInterrupt:
#    print("\nDetaching and exiting.")


