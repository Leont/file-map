#!perl

use strict;
use warnings;
use File::Map qw/:map lock_map sync/;
use IO::Handle;
use Test::More tests => 7;
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

throws_ok { map_handle my $mmaped, $fh, '>' } qr/^Can't map empty file writably at/, "Can't map empty file writably";

