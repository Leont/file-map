#!perl

use strict;
use warnings;
use File::Map qw/:map lock_map advise/;
use IO::Handle;
use Scalar::Util qw/tainted/;
use Test::More tests => 24;
use Test::Warnings;
use Test::Fatal qw/lives_ok/;

open my $self, '<:raw', $0 or die "Couldn't open self: $!";
my $slurped = do { local $/; <$self> };

{
	my $mmaped;
	lives_ok { map_handle($mmaped, $self, '<') } "map succeeded";
	ok(defined $mmaped,               "mmaped is defined");
	ok( length $mmaped > 300,         "length of mmaped is big enough");
	ok($mmaped eq $slurped,           "slurped is mmaped");
	is($mmaped, $slurped,             "slurped is mmaped");
	lives_ok { advise($mmaped, "normal") } "Advising";
	ok(!tainted($mmaped), 'map is not tainted');
}

close $self or die "Couldn't close self: $!";

{
	my $mmaped;
	lives_ok { map_file($mmaped, $0) } "map succeeded";
	ok(defined $mmaped,          "mmaped is defined");
	ok( length $mmaped > 300,    "length of mmaped is big enough");
	is($mmaped, $slurped,        "slurped is mmaped");

	lives_ok { unmap($mmaped) } "Unmapping";
}

{
	my %hash;
	lives_ok { map_file($hash{map}, $0) } 'mapping self into a hash';
	is($hash{map}, $slurped, 'Correctly autovifivies hash entry');
}

open my $copy, "+<:raw", undef or die "Couldn't create tempfile: $!";
$copy->autoflush(1);
print $copy $slurped;

{
	my $mmaped;
	lives_ok { map_handle($mmaped, $copy, '+<') } "map succeeded";
	ok(defined $mmaped,                  "mmaped is defined");
	ok( length $mmaped > 300,            "length of mmaped is big enough");
	is($mmaped, $slurped,                "slurped is mmaped");

	s/e/a/g for ($mmaped, $slurped);

	is($mmaped, $slurped, "slurped is mmaped after translation");

	$mmaped  =~ tr/r/t/ ;
	$slurped =~ tr/r/t/;

	is($mmaped, $slurped, "Translated");

	{
		no warnings 'substr';
		$mmaped = 1;
		like($mmaped, qr/^1/, '$mmaped should be like 1');

		my $ref = \$slurped;
		my $strval = "$ref";
		$mmaped = $ref;
		like($mmaped, qr/^\Q$strval\E/, '$mmaped should handle reference assignment');
	}
}


{
	lives_ok { map_anonymous(my $mmap, 4096) } "mapped an anonymous piece of memory";
}
