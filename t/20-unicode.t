#!perl 
use utf8;
use strict;
use warnings;

use open qw/:std :utf8/;

use File::Map qw/map_anonymous map_handle map_file/;
use Test::More $] >= 5.008_008 ? (tests => 14) : (skip_all => 'File::Map doesn\'t reliably support unicode on 5.8.7 and lower');
use Test::Warnings qw/warning warnings/;

my $builder = Test::More->builder;
binmode $builder->output,         ":utf8";
binmode $builder->failure_output, ":utf8";
binmode $builder->todo_output,    ":utf8";

my $example = 'Hállö wørld';

utf8::encode($example);

map_anonymous my $mapped, length $example;

is(warnings { substr $mapped, 0, length $example, $example }, 0, 'Assigning to $mapped gives no error');

ok !utf8::is_utf8($mapped), 'Mapped memory is bytes, not characters';

utf8::decode($example) or die 'Can\'t decode $example';

is(warnings { utf8::decode($mapped) }, 0, 'Can decode mapped');

ok utf8::is_utf8($mapped), 'Mapped memory is decoded to characters';

is $mapped, $example, '$mapped eq $example';

for my $var (substr $mapped, 0, length $mapped) {
	is(warnings { $var = uc $var }, 0, 'Indirect capitolization gives no warnings');
}

my $cap_example = 'HÁLLÖ WØRLD';

is $mapped, $cap_example, '$mapped is now capitalized';

# This is a TODO candidate
like(warning { $mapped = lc $mapped }, qr/Writing directly to a memory mapped file is not recommended at/, 'Direct capitolization gives a warnings');

is $mapped, lc $example, 'mapped is lowercased';

{
	open my $fh, '<:raw:utf8', $0;

	my $utf_mapped;

	is(warnings { map_handle $utf_mapped, $fh }, 0, 'Can map utf8 handle without warnings');

	ok utf8::is_utf8($utf_mapped), 'Mapped memory is decoded to characters automatically';
}

{
	my $utf_mapped;

	is(warnings { map_file $utf_mapped, $0, '<:raw:utf8' }, 0, 'Can map utf8 file without warnings');

	ok utf8::is_utf8($utf_mapped), 'Mapped memory is decoded to characters automatically';
}
