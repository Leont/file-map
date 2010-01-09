#!perl

use strict;
use warnings;
use File::Map qw/:map lock_map sync/;
use IO::Handle;
use Test::More tests => 8;
use Test::Warn;
use Test::Exception;


open my $fh, '+<', undef;

{
	my $mmaped;

	lives_ok { map_handle($mmaped, $fh) } "map succeeded";
	ok(defined $mmaped,                   "mmaped is defined");
	ok( length $mmaped == 0,              "length of mmaped is big enough");
	ok($mmaped eq "",                     "mmaped eq \"\"");
	is($mmaped, "",                       "mmaped is \"\"");

	lives_ok { sync $mmaped } "can fake syncing empty file";
}

{
	my $mmaped;
	lives_ok { map_handle $mmaped, $fh, '>' } "Can't map empty file writably";

	warnings_like { substr $mmaped, 0, 0, "1" } qr/^Can't overwrite an empty map at /, 'Shouldn\'t assign to empty map';
}

