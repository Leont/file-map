#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'Sys::Mmap::Simple' );
}

diag( "Testing Sys::Mmap::Simple $Sys::Mmap::Simple::VERSION, Perl $], $^X" );
