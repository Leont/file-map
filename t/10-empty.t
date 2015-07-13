#!perl

use strict;
use warnings;
use File::Map qw/:map lock_map sync/;
use IO::Handle;
use Test::More tests => 9;
use Test::Warnings 0.005 qw/warning/;
use Test::Fatal qw/lives_ok/;

open my $fh, '+<:raw', undef;

my $mmaped;

lives_ok { map_handle $mmaped, $fh } "map succeeded";
ok(defined $mmaped,                  "mmaped is defined");
cmp_ok(length $mmaped, '==', 0,      "length of mmaped is big enough");
ok($mmaped eq "",                    "mmaped eq \"\"");
is($mmaped, "",                      "mmaped is \"\"");

lives_ok { sync $mmaped } "can fake syncing empty file";

TODO: {
	todo_skip '5.8.7- gives spurious warnings', 2 if $] <= 5.008007;
	my $mmaped2;
	lives_ok { map_handle $mmaped2, $fh, '>' } "Can't map empty file writably";

	like(warning { substr $mmaped2, 0, 0, "1" }, qr/^Can't overwrite an empty map at /, 'Shouldn\'t assign to empty map');
}

foreach my $filename ( 1, 2 ) {
    my $input_filename = $0;
    map_file my $input, $input_filename, '<';
}
