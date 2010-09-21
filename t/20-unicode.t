#!perl 
use utf8;
use strict;
use warnings;

use File::Map qw/map_anonymous map_handle/;
use Test::More tests => 8;

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

for my $var (substr $mapped, 0, length $mapped) {
	warnings_like { $var = uc $var } [], 'Indirect capitolization gives no warnings';
}

my $cap_example = 'HÁLLÖ WØRLD';

is $mapped, $cap_example, '$mapped is now capitalized';

open my $fh, '<:utf8', $0;

warning_like { map_handle my $self, $fh } qr/Shouldn't mmap non-binary filehandle: layer 'utf8' is not binary at /, 'Can\'t map utf8 handle yet';
