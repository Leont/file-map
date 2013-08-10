#!perl

use strict;
use warnings;

use File::Map qw/:map lock_map sync advise/;
use IO::Socket::INET;
use Test::More tests => 27;
use Test::Warnings 0.005 qw/warning warnings/;
use Test::Fatal qw/exception lives_ok dies_ok/;
use if $^O ne 'MSWin32', POSIX => qw/setlocale LC_ALL/;

setlocale(&LC_ALL, 'C') if $^O ne 'MSWin32';

open my $self, '<:raw', $0 or die "Couldn't open self: $!";
my $slurped = do { local $/; <$self> };

my $mmaped;
lives_ok { map_anonymous $mmaped, length $slurped } 'Mapping succeeded';

substr $mmaped, 0, length $mmaped, $slurped;

is $mmaped, $slurped, '$slurped an $mmaped are equal';

like(warning { $mmaped = reverse $mmaped }, qr/^Writing directly to a memory mapped file is not recommended at /, 'Reversing should give a warning');

is($mmaped, scalar reverse($slurped), '$mmap is reversed');

{
	no warnings 'substr';
	is(warnings { $mmaped = reverse $mmaped }, 0, 'Reversing shouldn\'t give a warning when substr warnings are disabled');
}

is(warnings { $mmaped = $mmaped }, 0, 'No warnings on self-assignment');

dies_ok { map_file my $var, 'some-nonexistant-file' } 'Can\'t map non-existant files as readonly';

my @warnings = warnings { $mmaped =~ s/(.)/$1$1/ };
s/ at .*$//s for @warnings;
is_deeply(\@warnings, [ 'Writing directly to a memory mapped file is not recommended', 'Truncating new value to size of the memory map'], 'Trying to make it longer gives warnings');

is(warnings { $slurped =~ tr/r/t/ }, 0, 'Translation shouldn\'t cause warnings');

like(exception { sync my $foo }, qr/^Could not sync: this variable is not memory mapped at /, 'Can\'t sync normal variables');

like(exception { unmap my $foo }, qr/^Could not unmap: this variable is not memory mapped at /, 'Can\'t unmap normal variables');

like(exception { lock_map my $foo }, qr/^Could not lock_map: this variable is not memory mapped at /, 'Can\'t lock normal variables');

like(exception { map_anonymous my $foo, 0 }, qr/^Zero length specified for anonymous map at /, 'Have to provide a length for anonymous maps');

like(exception { &map_anonymous('foo', 1000) }, qr/^Modification of a read-only value attempted at /, 'Can\'t use literal as variable');

SKIP: {
	my $bound = IO::Socket::INET->new(Listen => 1, ReuseAddr => 1, LocalAddr => 'localhost') or skip "Couldn't make listening socket: $!", 1;
	like(exception { map_handle my $foo, $bound }, qr/^Could not map:/, 'Can\'t map STDOUT');
}

is(warnings { advise $mmaped, 'sequential' }, 0, 'advice $mmaped, \'readahead\'');
like(warning { advise $mmaped, 'non-existent' }, qr/^Unknown advice 'non-existent' at /, 'advice $mmaped, \'non-existent\'');

like(warning { $mmaped = "foo" }, qr/^Writing directly to a memory mapped file is not recommended at /, 'Trying to make it shorter gives a warning');

is(length $mmaped, length $slurped, '$mmaped and $slurped still have the same length');

like(warning { $mmaped = 1 }, qr/^Writing directly to a memory mapped file is not recommended at /, 'Cutting should give a warning for numbers too');

like(exception { map_file my $str, $0, '<', -1, 100; $str =~ tr/a// }, qr/^Window \(-?\d+,-?\d+\) is outside the file /, 'negative offsets give an error');

like(warning { undef $mmaped }, qr/^Writing directly to a memory mapped file is not recommended at/, 'Survives undefing');

map_anonymous our $local, 1024;

SKIP: {
	skip 'Your perl doesn\'t support hooking localization', 1 if $] < 5.008009;
	like(exception { local $local }, qr/^Can't localize file map at /, 'Localization throws an exception');
}

{
	my $mystring = 'hello';
	open my $fh, '<', \$mystring;
	like(exception { map_handle my ($map), $fh; }, qr/Can't map fake filehandle/, 'Mapping a scalar string handle throws an error');
}

my %hash;
lives_ok { map_anonymous $hash{'foo'}, 4096 } 'mapping a hash element shouldn\'t croak';

my $x;
my $y = \$x;

lives_ok { map_anonymous $y, 4096 } 'mapping to a reference shouldn\'t croak';
