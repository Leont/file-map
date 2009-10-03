#!perl

use strict;
use warnings;
use Test::More 'skip_all';#tests => 7;
use File::Map qw/:map protect/;
use IO::Handle;
use Test::Exception;

open my $copy, "+<", undef or die "Couldn't create tempfile: $!";
$copy->autoflush(1);
print $copy "0123456789"x10;

my $mmaped;
lives_ok { map_handle($mmaped, $copy, '+<') } "map succeeded";

my $howmany=$mmaped=~tr/9/_/;
is($mmaped, "012345678_"x10, "$howmany characters exchanged");

protect $mmaped, '<';
throws_ok { $mmaped=~tr/_/:/ } qr/Modification of a read-only value attempted/, 'now read only';
is($mmaped, "012345678_"x10, "still the same value");

protect $mmaped, '+<';
lives_ok { $mmaped=~tr/_/:/ } 'now writable again';
is($mmaped, "012345678:"x10, "written");

#my $pid;
#select undef, undef, undef, 0.1 unless defined($pid=fork);
#if( $pid ) {
#	waitpid $pid, 0;
#	is $?, SIGSEGV, 'got SIGSEGV as expected';
#} else {
#	protect $mmaped, '<';
#	substr $mmaped, 0, 3, "xxx";
#	die "Should have been dead\n";
#}

