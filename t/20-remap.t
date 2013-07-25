#!perl

use strict;
use warnings;
use Test::More $^O eq 'linux' ? (tests => 15) : skip_all => 'Only works on Linux';
use File::Map qw/map_handle map_anonymous remap/;
use Test::Exception;
use Test::Warnings;

open my $fh, '>', undef or die "Couln't open tempfile: $!\n";

print {$fh} "$_ pidgeons are evil\n" for 1 .. 1000;

my $map;
lives_ok { map_handle $map, $fh, '+>' } 'Can map tempfile';

is length $map, -s $fh, 'map length equals file length';

lives_ok { substr $map, 0, 1, '1' } 'Can write to start of map';

print {$fh} "$_ pidgeons are evil\n" for 1001 .. 2000;

lives_ok { remap $map, -s $fh } 'Can remap file';

is length $map, -s $fh, 'map length equals file length';

lives_ok { substr $map, 1, 1, '2' } 'Can write to start of map';

lives_ok { substr $map, -1, 1, '2' } 'Can write to end of map';

my $anon;
lives_ok { map_anonymous $anon, 4096, 'private' } 'Creating an anonymous mapping';

is length $anon, 4096, 'length of anonymous map is alright';

lives_ok { substr $anon, 0, 1, '1' } 'Can write to start of anonymous map';

lives_ok { remap $anon, 65535 } 'Can remap anonymous mapping';

is length $anon, 65535, '$anon is lengthened';

lives_ok { substr $anon, 1, 1, '2' } 'Can write to start of anonymous map';

lives_ok { substr $anon, -1, 1, "\0" } 'Can write to new end of anonymous map';

