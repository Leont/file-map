#!perl -T

use strict;
use warnings;
use Config;
use threads;
use Test::More $Config{useithreads} ? ( tests => 4 ) : ( skip_all => "No threading support enabled" );
use Sys::Mmap::Simple qw/map_anonymous sync :lock/;
use Time::HiRes qw/sleep time/;

map_anonymous my $variable, 1024;

substr $variable, 0, 5, "Horse";

my $counter;

my $thread = async {
	locked { wait_until { $counter++ } } $variable;
};

alarm 5;

sleep 1;
locked { notify } $variable;
$thread->join;

threads->create(\&sleeper, "Camel")->detach;

my @list = locked {
	my $start = time;
	my $foo = wait_until { substr($_, 0, 5) eq "Camel" };
	is($foo, 1, '$foo == 1');
	cmp_ok(time - 0.4, '>', $start, "Must have waited");
	is(substr($_, 0, 5), "Camel", 'Variable should contain "Camel"');
	(1, 2, 3);
} $variable;

is(@list, 3, "Length of list is 3");

sub sleeper {
	my $word = shift;
	locked { notify } $variable;
	sleep 1;
	locked {
		substr $_, 0, 5, $word;
		notify;
	} $variable;
}
