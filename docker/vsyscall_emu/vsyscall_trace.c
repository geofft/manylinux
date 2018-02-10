#define _GNU_SOURCE
#include <sys/auxv.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

const unsigned long VSYS_gettimeofday = 0xffffffffff600000,
                    VSYS_time = 0xffffffffff600400,
                    VSYS_getcpu = 0xffffffffff600800;
unsigned long VDSO_gettimeofday, VDSO_time, VDSO_getcpu;

unsigned long vdso_address(pid_t pid) {
	char *filename;
	asprintf(&filename, "/proc/%d/auxv", pid);
	int fd = open(filename, O_RDONLY);
	unsigned long buf[128];
	int i;
	read(fd, buf, sizeof(buf));
	close(fd);
	free(filename);
	for (i = 0; i < 128; i += 2) {
		if (buf[i] == AT_SYSINFO_EHDR) {
			return buf[i+1];
		} else if (buf[i] == 0) {
			return 0;
		}
	}
}

int handle_vsyscall(pid_t pid) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	if ((regs.rip & 0xfffffffffffff0ff) == 0xffffffffff600000) {
		printf("handling vsyscall for %d\n", pid);
		unsigned long vdso = vdso_address(pid);
		if (vdso_address == 0) {
			printf("couldn't find vdso\n");
			return 0;
		}
			
		if (regs.rip == VSYS_gettimeofday) {
			regs.rip = vdso | VDSO_gettimeofday;
		} else if (regs.rip == VSYS_time) {
			regs.rip = vdso | VDSO_time;
		} else if (regs.rip == VSYS_getcpu) {
			regs.rip = vdso | VDSO_getcpu;
		} else {
			printf("invalid vsyscall %x\n", regs.rip);
			return 0;
		}
		ptrace(PTRACE_SETREGS, pid, 0, &regs);
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	void *vdso = dlopen("linux-vdso.so.1", RTLD_LAZY | RTLD_NOLOAD);
	VDSO_gettimeofday = (unsigned long)dlsym(vdso, "__vdso_gettimeofday") & 0xfff;
	VDSO_time = (unsigned long)dlsym(vdso, "__vdso_time") & 0xfff;
	VDSO_getcpu = (unsigned long)dlsym(vdso, "__vdso_getcpu") & 0xfff;

	if (argc < 2) {
		printf("usage: vsyscall_trace <pid>");
		return 1;
	}
	pid_t pid = atoi(argv[1]);
	if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE) != 0) {
		perror("PTRACE_SEIZE");
		return 1;
	}
	int wstatus;
	while ((pid = waitpid(-1, &wstatus, 0)) != -1) {
		if (WIFSTOPPED(wstatus)) {
			if (WSTOPSIG(wstatus) == SIGSEGV && handle_vsyscall(pid)) {
				ptrace(PTRACE_CONT, pid, 0, 0);
			} else {
				ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(wstatus));
			}
		}
	}
}
