#!perl -T

use strict;
use warnings;
use Config;
use Test::More $Config{useithreads} ? ( tests => 5 ) : ( skip_all => "No threading support enabled" );
use threads;
use File::Map qw/map_anonymous sync :lock/;
use Time::HiRes qw/sleep time/;

map_anonymous my $variable, 1024;

substr $variable, 0, 5, "Horse";

my $counter;

alarm 10;

my $thread1 = async {
	lock_map $variable;
	wait_until { $counter++ } $variable;
};

sleep 1;
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

sleep 1;
{
	lock_map $variable;
	notify $variable;
}
$thread2->join;

ok(1, "Second notification worked");

threads->create(\&sleeper, "Camel")->detach;

{
	lock_map $variable;
	my $start = time;
	my $foo = wait_until { substr($_, 0, 5) eq "Camel" } $variable;
	is($foo, 1, '$foo == 1');
	cmp_ok(time - 0.4, '>', $start, "Must have waited");
	is(substr($variable, 0, 5), "Camel", 'Variable should contain "Camel"');
}

sub sleeper {
	sleep 1;
	my $word = shift;
	{
		lock_map $variable;
		notify $variable;
	}
	sleep 1;
	{
		lock_map $variable;
		substr $variable, 0, 5, $word;
		notify $variable;
	}
}

