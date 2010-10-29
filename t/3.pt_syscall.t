use strict;
use Test::More;
Test::More->builder->use_numbers(0);
Test::More->builder->no_ending(1);

use Linux::x86_64::Ptrace;
use Linux::x86_64::Ptrace::Syscall;
use POSIX qw(:sys_wait_h);

my $pid = fork();
my $calls;

if ( $pid == 0 ) {
    pt_trace_me();
    exec('/bin/ls');
}
else {
    while (1) {
        last if ( wait() == -1 );
        my $call = pt_getcall($pid);
        pt_syscall($pid);
        diag( "syscall is ", $SYS{$call} );
        $calls++;
    }
    cmp_ok( $calls, '>=', 100, 'syscalls'); 
    done_testing(1);
}
