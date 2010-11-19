#!perl -T

use Test::More tests => 2;
use Test::NoWarnings;

BEGIN {
	use_ok( 'File::Map' );
}

diag( "Testing File::Map $File::Map::VERSION, Perl $], $^X" );
