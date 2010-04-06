#!perl

use utf8;
use strict;
use warnings;

use File::Map qw/map_anonymous/;
use Test::More tests => 7;

use Test::Warn;

my $example = 'Hállö wørld';

utf8::encode($example);

map_anonymous my $mapped, length $example;

warnings_like { substr $mapped, 0, length $example, $example } [], 'Assigning to $mapped gives no error';

ok !utf8::is_utf8($mapped), 'Mapped memory is bytes, not characters';

utf8::decode($example) or die 'Can\'t decode $example';

warnings_like { utf8::decode($mapped) } [], 'Can decode mapped';

ok utf8::is_utf8($mapped), 'Mapped memory is decoded to characters';

is $mapped, $example, '$mapped eq $example';

for (substr $mapped, 0, length $mapped) {
	warnings_like { $_ = uc $_ } [], 'Indirect capitolization gives no warnings';
}

my $cap_example = 'HÁLLÖ WØRLD';

is $mapped, $cap_example, '$mapped is now capitalized';
