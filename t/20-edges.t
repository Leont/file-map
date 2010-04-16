#!perl

use strict;
use warnings;

use File::Map qw/map_anonymous/;
use Test::More tests => 2;
use Test::Exception;

my %hash;
lives_ok { map_anonymous $hash{'foo'}, 4096 } 'mapping a hash element shouldn\'t croak';

my $x;
my $y = \$x;

lives_ok { map_anonymous $y, 4096 } 'mapping to a reference shouldn\'t croak';
