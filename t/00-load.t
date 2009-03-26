#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'File::Map' );
}

diag( "Testing File::Map $File::Map::VERSION, Perl $], $^X" );
