#!perl

use strict;
use warnings;
use File::Map qw/:map lock_map sync/;
use IO::Handle;
use Test::More tests => 9;
use Test::Warnings qw/warning/;
use Test::Exception;

open my $fh, '+<:raw', undef;

my $mmaped;

lives_ok { map_handle $mmaped, $fh } "map succeeded";
ok(defined $mmaped,                  "mmaped is defined");
cmp_ok(length $mmaped, '==', 0,      "length of mmaped is big enough");
ok($mmaped eq "",                    "mmaped eq \"\"");
is($mmaped, "",                      "mmaped is \"\"");

lives_ok { sync $mmaped } "can fake syncing empty file";

{
	local $SIG{__WARN__} = $] >= 5.008007 ? $SIG{__WARN__}: sub {};
	my $mmaped2;
	lives_ok { map_handle $mmaped2, $fh, '>' } "Can't map empty file writably";

	like(warning { substr $mmaped2, 0, 0, "1" }, qr/^Can't overwrite an empty map at /, 'Shouldn\'t assign to empty map');
}
