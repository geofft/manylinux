#define _GNU_SOURCE
#include <sys/auxv.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef DEBUG
#define debug_printf printf
#else
#define debug_printf(...) 0
#endif

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
		debug_printf("handling vsyscall for %d\n", pid);
		unsigned long vdso = vdso_address(pid);
		if (vdso_address == 0) {
			debug_printf("couldn't find vdso\n");
			return 0;
		}

		if (regs.rip == VSYS_gettimeofday) {
			regs.rip = vdso | VDSO_gettimeofday;
		} else if (regs.rip == VSYS_time) {
			regs.rip = vdso | VDSO_time;
		} else if (regs.rip == VSYS_getcpu) {
			regs.rip = vdso | VDSO_getcpu;
		} else {
			debug_printf("invalid vsyscall %x\n", regs.rip);
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
	pid_t pid, child_pid = 0;
	int wstatus, child_wstatus = 0;

	if (argc < 2) {
		printf("usage: vsyscall_trace -p <pid>...\n");
		printf("       vsyscall_trace <cmd> [args...]\n");
		return 1;
	}

	if (strcmp(argv[1], "-p") == 0) {
		int i;
		for (i = 2; i < argc; i++) {
			pid = atoi(argv[i]);
			if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE) != 0) {
				perror("PTRACE_SEIZE");
				return 1;
			}
		}
	} else {
		child_pid = fork();
		if (child_pid == -1) {
			perror("fork");
			return 1;
		} else if (child_pid == 0) {
			raise(SIGSTOP);
			execvp(argv[1], &argv[1]);
			perror("execvp");
			return 1;
		} else {
			if (ptrace(PTRACE_SEIZE, child_pid, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE) != 0) {
				perror("PTRACE_SEIZE");
				return 1;
			}
			kill(child_pid, SIGCONT);
		}
	}

	while ((pid = waitpid(-1, &wstatus, 0)) != -1) {
		if (WIFSTOPPED(wstatus)) {
			if (WSTOPSIG(wstatus) == SIGSEGV && handle_vsyscall(pid)) {
				ptrace(PTRACE_CONT, pid, 0, 0);
			} else {
				ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(wstatus));
			}
		} else if (pid == child_pid && WIFEXITED(wstatus)) {
			child_wstatus = wstatus;
		}
	}
	if (errno != ECHILD) {
		perror("waitpid");
		return 1;
	}
	if (WIFSIGNALED(wstatus)) {
		raise(WTERMSIG(wstatus));
		return 1;
	} else {
		return WEXITSTATUS(wstatus);
	}
}
