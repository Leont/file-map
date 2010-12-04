#!perl -T

use strict;
use warnings;
use Config;
BEGIN {
	# Yes, this is really necessary
	if ($Config{useithreads}) {
		require threads;
		threads->import();
		require Test::More;
		Test::More->import(tests => 7);
	}
	else {
		require Test::More;
		Test::More->import(skip_all => "No threading support enabled");
	}
}
use File::Map qw/map_anonymous sync :lock/;
use Time::HiRes qw/sleep time/;
use Test::NoWarnings;

map_anonymous my $variable, 1024;

substr $variable, 0, 5, "Horse";

my $counter;

alarm 5;

my $thread1 = async {
	lock_map $variable;
	wait_until { $counter++ } $variable;
	is($counter, 2, 'Counter is 2');
};

sleep .1;
do {
	lock_map $variable;
	notify $variable;
};
$thread1->join;

ok(1, "First notification worked");

my $thread2 = async {
	lock_map $variable;
	wait_until { $counter++ } $variable;
};

sleep .1;
{
	lock_map $variable;
	notify $variable;
}
$thread2->join;

ok(1, "Second notification worked");

{
	my $start = time;
	threads->create(\&sleeper, "Camel")->detach;

	lock_map $variable;
	my $foo = wait_until { substr($_, 0, 5) eq "Camel" } $variable;
	is($foo, 1, '$foo == 1');
	cmp_ok(time - $start, '>', 0.2, "Must have waited");
	is(substr($variable, 0, 5), "Camel", 'Variable should contain "Camel"');
}

sub sleeper {
	sleep .1;
	my $word = shift;
	{
		lock_map $variable;
		notify $variable;
	}
	sleep .1;
	{
		lock_map $variable;
		substr $variable, 0, 5, $word;
		notify $variable;
	}
}

