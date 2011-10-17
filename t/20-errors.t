#!perl

use strict;
use warnings;

use File::Map qw/:map lock_map sync advise/;
use IO::Socket::INET;
use Test::More tests => 27;
use Test::Warn;
use Test::Exception;
use Test::NoWarnings;
use if $^O ne 'MSWin32', POSIX => qw/setlocale LC_ALL/;

setlocale(&LC_ALL, 'C') if $^O ne 'MSWin32';

open my $self, '<:raw', $0 or die "Couldn't open self: $!";
my $slurped = do { local $/; <$self> };

my $mmaped;
lives_ok { map_anonymous $mmaped, length $slurped } 'Mapping succeeded';

substr $mmaped, 0, length $mmaped, $slurped;

is $mmaped, $slurped, '$slurped an $mmaped are equal';

warning_like { $mmaped = reverse $mmaped } qr/^Writing directly to a memory mapped file is not recommended at /, 'Reversing should give a warning';

is($mmaped, scalar reverse($slurped), '$mmap is reversed');

{
	no warnings 'substr';
	warning_like { $mmaped = reverse $mmaped } undef, 'Reversing shouldn\'t give a warning when substr warnings are disabled';
}

warning_is { $mmaped = $mmaped } undef, 'No warnings on self-assignment';

dies_ok { map_file my $var, 'some-nonexistant-file' } 'Can\'t map non-existant files as readonly';

warnings_like { $mmaped =~ s/(.)/$1$1/ } [ qr/^Writing directly to a memory mapped file is not recommended at /, qr/^Truncating new value to size of the memory map at /], 'Trying to make it longer gives warnings';

warning_is { $slurped =~ tr/r/t/ } undef, 'Translation shouldn\'t cause warnings';

throws_ok { sync my $foo } qr/^Could not sync: this variable is not memory mapped at /, 'Can\'t sync normal variables';

throws_ok { unmap my $foo } qr/^Could not unmap: this variable is not memory mapped at /, 'Can\'t unmap normal variables';

throws_ok { lock_map my $foo } qr/^Could not lock_map: this variable is not memory mapped at /, 'Can\'t lock normal variables';

throws_ok { map_anonymous my $foo, 0 } qr/^Zero length specified for anonymous map at /, 'Have to provide a length for anonymous maps';

throws_ok { &map_anonymous('foo', 1000) } qr/^Modification of a read-only value attempted at /, 'Can\'t use literal as variable';

SKIP: {
	my $bound = IO::Socket::INET->new(Listen => 1, ReuseAddr => 1, LocalAddr => 'localhost') or skip "Couldn't make listening socket: $!", 1;
	throws_ok { map_handle my $foo, $bound } qr/^Could not map: Permission denied/, 'Can\'t map STDOUT';
}

warning_is { advise $mmaped, 'sequential' } undef, 'advice $mmaped, \'readahead\'';
warning_like { advise $mmaped, 'non-existent' } qr/^Unknown advice 'non-existent' at /, 'advice $mmaped, \'non-existent\'';

warning_like { $mmaped = "foo" } qr/^Writing directly to a memory mapped file is not recommended at /, 'Trying to make it shorter gives a warning';

is(length $mmaped, length $slurped, '$mmaped and $slurped still have the same length');

warning_like { $mmaped = 1 } qr/^Writing directly to a memory mapped file is not recommended at /, 'Cutting should give a warning for numbers too';

throws_ok { map_file my $str, $0, '<', -1, 100; $str =~ tr/a// } qr/^Window \(-?\d+,-?\d+\) is outside the file /, 'negative offsets give an error';

warnings_like { undef $mmaped } [ qr/^Writing directly to a memory mapped file is not recommended at/ ], 'Survives undefing';

map_anonymous our $local, 1024;

SKIP: {
	skip 'Your perl doesn\'t support hooking localization', 1 if $] < 5.008009;
	throws_ok { local $local } qr/^Can't localize file map at /, 'Localization throws an exception';
}

{
	my $mystring = 'hello';
	open my $fh, '<', \$mystring;
	throws_ok { map_handle my ($map), $fh; } qr/Can't map fake filehandle/, 'Mapping a scalar string handle throws an error';
}

my %hash;
lives_ok { map_anonymous $hash{'foo'}, 4096 } 'mapping a hash element shouldn\'t croak';

my $x;
my $y = \$x;

lives_ok { map_anonymous $y, 4096 } 'mapping to a reference shouldn\'t croak';
