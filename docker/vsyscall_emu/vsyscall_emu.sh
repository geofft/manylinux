#!/bin/sh

gdb -x vsyscall_emu.gdb --batch-silent --return-child-result --args "$@"
