use strict;
use Test::More;
Test::More->builder->use_numbers(0);
Test::More->builder->no_ending(1);

use Linux::x86_64::Ptrace;
use Linux::x86_64::Ptrace::Syscall;

my $pid = fork();

if ( $pid == 0 ) {
    sleep 2;
    diag( "child done" );
}
else {
    diag( "pt_attach", pt_attach($pid));
    wait();
    ok( defined( my $call = pt_getcall($pid) ), 'pt_getcall' );
    ok( defined( pt_detach($pid) ), 'pt_detach' );
    diag( "syscall is ", $SYS{$call} );
    done_testing(2);
}
