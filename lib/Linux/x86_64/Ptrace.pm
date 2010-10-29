package Linux::x86_64::Ptrace;

use 5.012001;
use strict;
use warnings;
use XSLoader;

use base qw(Exporter);
our $VERSION = '0.01';

our @EXPORT = qw(
  ptrace pt_trace_me pt_continue pt_kill pt_attach pt_detach
  pt_syscall pt_getcall pt_setcall pt_peekstr
  PT_ATTACH
  PT_CONTINUE
  PT_DETACH
  PT_GETEVENTMSG
  PT_GETFPREGS
  PT_GETFPXREGS
  PT_GETREGS
  PT_GETSIGINFO
  PT_KILL
  PT_READ_D
  PT_READ_I
  PT_READ_U
  PT_SETFPREGS
  PT_SETFPXREGS
  PT_SETOPTIONS
  PT_SETREGS
  PT_SETSIGINFO
  PT_STEP
  PT_SYSCALL
  PT_TRACE_ME
  PT_WRITE_D
  PT_WRITE_I
  PT_WRITE_U
);

our %EXPORT_TAGS = ( 'all' => [qw()] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

XSLoader::load( 'Linux::x86_64::Ptrace', $VERSION );

use constant {
    PT_TRACE_ME    => 0,
    PT_READ_I      => 1,
    PT_READ_D      => 2,
    PT_READ_U      => 3,
    PT_WRITE_I     => 4,
    PT_WRITE_D     => 5,
    PT_WRITE_U     => 6,
    PT_CONTINUE    => 7,
    PT_KILL        => 8,
    PT_STEP        => 9,
    PT_GETREGS     => 12,
    PT_SETREGS     => 13,
    PT_GETFPREGS   => 14,
    PT_SETFPREGS   => 15,
    PT_ATTACH      => 16,
    PT_DETACH      => 17,
    PT_GETFPXREGS  => 18,
    PT_SETFPXREGS  => 19,
    PT_SYSCALL     => 24,
    PT_SETOPTIONS  => 0x4200,
    PT_GETEVENTMSG => 0x4201,
    PT_GETSIGINFO  => 0x4202,
    PT_SETSIGINFO  => 0x4203,
};

use Linux::x86_64::Ptrace::Syscall;
use Class::Struct 'Linux::x86_64::Struct::Regs' => [
    r15      => '$',
    r14      => '$',
    r13      => '$',
    r12      => '$',
    rbp      => '$',
    rbx      => '$',
    r11      => '$',
    r10      => '$',
    r9       => '$',
    r8       => '$',
    rax      => '$',
    rcx      => '$',
    rdx      => '$',
    rsi      => '$',
    orig_rax => '$',
    rip      => '$',
    cs       => '$',
    eflags   => '$',
    rsp      => '$',
    ss       => '$',
];

*ptrace = \&pt_ptrace;

sub pt_trace_me() { ptrace( PT_TRACE_ME, 0, 0, 0 ) }

## wrapper are there
#sub pt_read_i() { ptrace(PT_READ_I)}
#sub pt_read_d() { ptrace(PT_READ_D)}
#sub pt_read_u() { ptrace(PT_READ_U)}
#sub pt_write_i() { ptrace(PT_WRITE_I)}
#sub pt_wirte_d() { ptrace(PT_WRITE_D)}
#sub pt_write_u() { ptrace(PT_WRITE_U)}

sub pt_continue($) { ptrace( PT_CONTINUE, $_[0], 0, 0 ) }
sub pt_kill($)     { ptrace( PT_KILL,     $_[0], 0, 0 ) }

#sub pt_step() { ptrace(PT_STEP)}
#sub pt_getregs() { ptrace(PT_GETREGS)}
#sub pt_setregs() { ptrace(PT_SETREGS)}
#sub pt_getfpregs() { ptrace(PT_GETFPREGS)}
#sub pt_setfpregs() { ptrace(PT_SETFPREGS)}

sub pt_attach($) { ptrace( PT_ATTACH, $_[0], 0, 0 ) }
sub pt_detach($) { ptrace( PT_DETACH, $_[0], 0, 0 ) }

#sub pt_getfpxregs() { ptrace(PT_GETFPXREGS)}
#sub pt_setfpxregs() { ptrace(PT_SETFPXREGS)}

sub pt_syscall($) { ptrace( PT_SYSCALL, $_[0], 0, 0 ) }

#sub pt_setoptions() { ptrace(PT_SETOPTIONS)}
#sub pt_geteventmsg() { ptrace(PT_GETEVENTMSG)}
#sub pt_getsiginfo() { ptrace(PT_GETSIGINFO)}
#sub pt_setsiginfo() { ptrace(PT_SETSIGINFO)}

sub pt_getcall($) { xs_getcall( $_[0] ) }           # <- replace read_u
sub pt_setcall($$) { xs_setcall( $_[0], $_[1] ) }    # <- replace write_u

sub pt_peekstr {    # <- replace pt_read_i, pt_read_d
    my ( $pid, $addr ) = @_;
    my $str = '';
    while (1) {
        my $int = ptrace( PT_READ_D, $pid, $addr, 0 );
        for my $c ( unpack( "C*", pack "Q", $int ) ) {
            return $str unless $c;
            $str .= $c;
        }
        $addr += 8;
    }
}

#sub pt_pokestr(){} # <- replace pt_write_i, pt_write_d

1;
__END__

=head1 NAME

Linux::x86_64::Ptrace 

=head1 SYNOPSIS

  use Linux::x86_64::Ptrace;
  use Linux::x86_64::Ptrace::Syscall;

=head1 DESCRIPTION

Linux::x86_64::Ptrace is a ptrace (process trace) wrapper for x86_64 Linux.
I refered API from FreeBSD::x86_64::Ptrace.

=head2 EXPORT

  pt_trace_me()
  pt_continue()
  pt_kill()
  pt_attach()
  pt_detach()
  pt_syscall()
  pt_getcall()
# pt_setcall()
# pt_peekstr()

See t/* scripts for how to use.

=head1 SEE ALSO

Playing with ptrace ( http://www.linuxjournal.com/article/6100?page=0,0 )
is a best start point to handle ptrace.

=head1 AUTHOR

DAIBA, Keiichi daiba@cpan.org

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by DAIBA, Keiichi

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
