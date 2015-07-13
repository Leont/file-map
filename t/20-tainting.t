#! perl -T

use strict;
use warnings;
use Test::More;
use Test::Fatal 'lives_ok';
use File::Map qw/:map lock_map advise/;
use Scalar::Util qw/tainted/;

plan skip_all => 'No taint support' if not tainted($0);

my $map;
lives_ok { map_file($map, $0) } 'Can map under tainting';

ok(tainted($map), 'mapped file is tainted');

ok(substr($map, 1, 10), 'substring from mapping is also tainted');

my $piece = substr($map, 1, 10);

ok(tainted($piece), 'copy of substring from mapping is also tainted');

done_testing;
