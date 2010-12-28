#!perl 
use utf8;
use strict;
use warnings;

use open qw/:std :utf8/;

use File::Map qw/map_anonymous map_handle map_file/;
use Test::More tests => 14;
use Test::NoWarnings;

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

# This is a TODO candidate
warnings_like { $mapped = lc $mapped } qr/Writing directly to a memory mapped file is not recommended at/, 'Direct capitolization gives a warnings';

is $mapped, lc $example, 'mapped is lowercased';

{
	open my $fh, '<:raw:utf8', $0;

	my $utf_mapped;

	warning_like { map_handle $utf_mapped, $fh } undef, 'Can map utf8 handle';

	ok utf8::is_utf8($utf_mapped), 'Mapped memory is decoded to characters automatically';
}

{
	my $utf_mapped;

	warning_like { map_file $utf_mapped, $0, '<:utf8' } undef, 'Can map utf8 file';

	ok utf8::is_utf8($utf_mapped), 'Mapped memory is decoded to characters automatically';
}
