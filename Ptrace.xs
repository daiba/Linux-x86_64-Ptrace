#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <asm/user.h>
#include <sys/reg.h>

MODULE = Linux::x86_64::Ptrace		PACKAGE = Linux::x86_64::Ptrace		

PROTOTYPES: ENABLE

long
pt_ptrace(request, pid, addr, data)
    int request;
    int pid;
    long addr;
    long data;
CODE:
    RETVAL = ptrace(request, pid, addr, data);
OUTPUT:
    RETVAL

long
xs_getcall(pid)
    int pid;
CODE:
    RETVAL = ptrace(PT_READ_U, pid, 8 * ORIG_RAX, 0);
OUTPUT:
    RETVAL

int
xs_setcall(pid, call)
    int pid;
    long call;
CODE:
    RETVAL = ptrace(PT_WRITE_U, pid, 8 * ORIG_RAX, call);
OUTPUT:
    RETVAL

PROTOTYPES: DISABLE

void
xs_getregs(pid)
    int pid;
CODE:
    struct user_regs_struct r;
    ptrace(PT_GETREGS, pid, r, 0);
    EXTEND(SP, 26);
    ST(0)  = newSViv(r.r15);
    ST(1)  = newSViv(r.r14);
    ST(2)  = newSViv(r.r13);
    ST(3)  = newSViv(r.r12);
    ST(4)  = newSViv(r.rbp);
    ST(5)  = newSViv(r.rbx);
    ST(6)  = newSViv(r.r11);
    ST(7)  = newSViv(r.r10);
    ST(8)  = newSViv(r.r9);
    ST(9)  = newSViv(r.r8);
    ST(10) = newSViv(r.rax);
    ST(11) = newSViv(r.rcx);
    ST(12) = newSViv(r.rdx);
    ST(13) = newSViv(r.rsi);
    ST(14) = newSViv(r.rdi);
    ST(15) = newSViv(r.orig_rax);
    ST(16) = newSViv(r.rip);
    ST(17) = newSViv(r.cs);
    ST(18) = newSViv(r.eflags);
    ST(19) = newSViv(r.rsp);
    ST(20) = newSViv(r.ss);
    ST(21) = newSViv(r.fs_base);
    ST(22) = newSViv(r.gs_base);
    ST(23) = newSViv(r.ds);
    ST(24) = newSViv(r.es);
    ST(25) = newSViv(r.fs);
    ST(26) = newSViv(r.gs);
    XSRETURN(27);
	

void
xs_setregs(pid, r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs )
    int pid;
    long r15; long r14; long r13; long r12;
    long rbp; long rbx; long r11; long r10;
    long r9; long r8; long rax; long rcx;
    long rdx; long rsi; long rdi; long orig_rax;
    long rip; long cs; long eflags;
    long rsp; long ss;
    long fs_base; long gs_base;
    long ds; long es; long fs; long gs; 
CODE:
{
    struct user_regs_struct r;
    r.r15 = r15;
    r.r14 = r14;
    r.r13 = r13;
    r.r12 = r12;
    r.rbp = rbp;
    r.rbx = rbx; 
    r.r11 = r11;
    r.r10 = r10;
    r.r9  = r9;
    r.r8  = r8;
    r.rax = rax;
    r.rcx = rcx;
    r.rdx = rdx;
    r.rsi = rsi;
    r.rdi = rdi;
    r.orig_rax = orig_rax;
    r.rip = rip;
    r.cs  = cs;
    r.eflags = eflags;
    r.rsp = rsp;
    r.ss  = ss;
    r.fs_base = fs_base;
    r.gs_base = gs_base;
    r.ds  = ds;
    r.es  = es;
    r.fs  = fs;
    r.gs  = gs;
    ST(0) = newSViv(ptrace(PT_SETREGS, pid, (caddr_t)&r, 0));
    XSRETURN(1);
}

