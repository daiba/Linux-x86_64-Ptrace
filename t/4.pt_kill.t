use strict;
use Test::More;
Test::More->builder->use_numbers(0);
Test::More->builder->no_ending(1);

use Linux::x86_64::Ptrace;
use Linux::x86_64::Ptrace::Syscall;
use POSIX qw(:sys_wait_h);

my $pid = fork();
my $calls = 0;

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
        if ( $calls == 4 ) {
            is( pt_kill($pid), 0, "pt_kill " );
        }
        $calls++;
    }
    is( $calls, 6, 'calls' );
    done_testing(2);
}
