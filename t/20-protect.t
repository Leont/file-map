#!perl

use strict;
use warnings;
use Test::More tests => 8;
use File::Map qw/:map protect PROT_NONE/;
use IO::Handle;
use Test::Fatal qw/lives_ok exception/;
use Test::Warnings;

open my $copy, "+<:raw", undef or die "Couldn't create tempfile: $!";
$copy->autoflush(1);
print $copy "0123456789"x10;

my $mmaped;
lives_ok { map_handle($mmaped, $copy, '+<') } "map succeeded";

my $howmany = $mmaped =~ tr/9/_/;
is($mmaped, "012345678_" x 10, "$howmany characters exchanged");

protect $mmaped, '<';
like(exception { $mmaped =~ tr/_/:/ }, qr/Modification of a read-only value attempted/, 'now read only');
is($mmaped, "012345678_" x 10, "still the same value");

protect $mmaped, '+<';
lives_ok { $mmaped =~ tr/_/:/ } 'now writable again';
is($mmaped, "012345678:" x 10, "written");

SKIP: {
	skip("Fork doesn't work as expected on Windows", 1) if $^O eq "MSWin32";
	fail("Could not fork!") if not defined (my $pid = fork);
	if ($pid) {
		waitpid $pid, 0;
		ok $? & 127, 'got SIGSEGV as expected';
	}
	else {
		protect $mmaped, PROT_NONE;
		my $var = substr $mmaped, 0, 3;
		die "Should have been dead\n";
	}
}
