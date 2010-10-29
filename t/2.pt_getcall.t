use strict;
use Test::More;
Test::More->builder->use_numbers(0);
Test::More->builder->no_ending(1);

use Linux::x86_64::Ptrace;
use Linux::x86_64::Ptrace::Syscall;

my $pid = fork();

if ( $pid == 0 ) {
    pt_trace_me();
    exec('/bin/ls');
}
else {
    wait();
    ok( defined( my $call = pt_getcall($pid) ), 'pt_getcall' );
    ok( defined( pt_continue($pid) ), 'pt_continue' );
    is( $SYS{$call}, 'execve', 'execve' );
    diag( "syscall is ", $SYS{$call} );
    done_testing(3);
}
