use strict;
use Test::More tests => 1;

use Linux::x86_64::Ptrace;

is( pt_trace_me(), 0, "pt_trace_me");
