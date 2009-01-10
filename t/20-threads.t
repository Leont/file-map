#!perl -T

use strict;
use warnings;
use Config;
use Test::More $Config{useithreads} ? ( tests => 5 ) : ( skip_all => "No threading support enabled" );
use threads 1.34;
use Sys::Mmap::Simple qw/map_anonymous sync locked :CONDITION/;

map_anonymous my $variable, 1024;

substr $variable, 0, 5, "Horse";

my $counter;

my $thread = async {
	locked { condition_wait { $counter++ } } $variable;
};

alarm 5;

sleep 1;
ok($thread->is_running, "Thread is running");
locked { condition_signal } $variable;
$thread->join;

threads->create(\&sleeper, "Camel")->detach;

my @list = locked {
	my $start = time;
	my $foo = condition_wait { substr($_, 0, 5) eq "Camel" };
	is($foo, 1, '$foo == 1');
	ok(time - $start > 1, "Two seconds must have passed");
	is(substr($_, 0, 5), "Camel", 'Variable should contain "Camel"');
	(1, 2, 3);
} $variable;

is(@list, 3, "Length of list is 3");

sub sleeper {
	my $word = shift;
	sleep 2;
	locked {
		condition_signal;
		substr $_, 0, 5, $word;
		condition_signal;
	} $variable;
}
