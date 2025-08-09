#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = """
int hello_world(void *ctx) {
    bpf_trace_printk("Hello World!\\n");
    return 0;
}
"""

b = BPF(text=program, cflags=["-Wno-macro-redefined"])
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello_world")

#print("Tracing clone syscalls... Ctrl-C to exit.")
print("Tracing clone syscalls... ")

# b.trace_print()

try:
    while True:
        line = b.trace_readline()
        if line:
            print(line.decode('utf-8', errors='replace'), end='\n', flush=True)
except KeyboardInterrupt:
    print("\nDetaching and exiting.")


