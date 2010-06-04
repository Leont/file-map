#! /usr/bin/perl

use 5.010;
use strict;
use warnings;

use File::Map qw/map_file advise/;

die "Not enough arguments given\n" if @ARGV < 2;

my $regex = shift;
$regex = qr/$regex/;

for my $filename (@ARGV) {
	map_file my($map), $filename;
	advise $map, 'sequential';
	my $match = $map =~ $regex ? "" : "n't";
	say "File '$filename' does$match match";
}
