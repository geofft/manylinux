#!/bin/bash
#
# Test vsyscall_trace, either on a docker image if a name is provided or
# directly on the host otherwise.

# Stop at any error, show all commands
set -ex

# Get build utilities
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../build_scripts/build_utils.sh

# Run the kernel vsyscall test command with a fake vsyscall page
# address, so that we're guaranteed that the host kernel will segfault
# on the attempted vsyscalls.
curl -sSLO https://github.com/torvalds/linux/raw/v4.15/tools/testing/selftests/x86/test_vsyscall.c
check_sha256sum test_vsyscall.c ff55a0c8ae2fc03a248a7fa1c47ba00bfe73abcef09606b6708e01f246a4f2b5
sed -i 's/VSYS(0xffffffffff6/VSYS(0xfffffffffe6/' test_vsyscall.c
# Also, we don't implement read support for the vsyscall page, so don't test it.
sed -i '/test_vsys_r();/d' test_vsyscall.c
cc -ggdb3 -o test_vsyscall test_vsyscall.c -ldl

if [ -n "$1" ]; then
    docker run -v .:/vsyscall_emu --rm --entrypoint /vsyscall_emu/vsyscall_trace_test "$1" /vsyscall_emu/test_vsyscall
else
    ./vsyscall_trace_test ./test_vsyscall
fi

rm -f test_vsyscall test_vsyscall.c
