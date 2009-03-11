#!perl

use strict;
use warnings;
use Sys::Mmap::Simple qw/:map locked sync/;
use IO::Handle;
use Test::More tests => 19;
use Test::Warn;

open my $self, '<', $0 or die "Couldn't open self: $!";
my $slurped = do { local $/; <$self> };

{
ok(map_handle(my $mmaped, $self), "map succeeded");
ok(defined $mmaped,               "mmaped is defined");
ok( length $mmaped > 300,         "length of mmaped is big enough");
ok($mmaped eq $slurped,           "slurped is mmaped");
is($mmaped, $slurped,             "slurped is mmaped");
ok(sync($mmaped), "Syncing");
}

close $self or die "Couldn't close self: $!";

{
ok(map_file(my $mmaped, $0), "map succeeded");
ok(defined $mmaped,          "mmaped is defined");
ok( length $mmaped > 300,    "length of mmaped is big enough");
is($mmaped, $slurped,        "slurped is mmaped");

ok(unmap($mmaped), "Unmapping");
}

open my $copy, "+<", undef or die "Couldn't create tempfile: $!";
$copy->autoflush(1);
print $copy $slurped;

{
ok(map_handle(my $mmaped, $copy, '+<'), "map succeeded");
ok(defined $mmaped,                  "mmaped is defined");
ok( length $mmaped > 300,            "length of mmaped is big enough");
is($mmaped, $slurped,                "slurped is mmaped");

s/e/a/g for ($mmaped, $slurped);

is($mmaped, $slurped, "slurped is mmaped after translation");

locked { is($_, $slurped, '$_ == $slurped') } $mmaped;

locked { tr/r/t/ }  $mmaped;
$slurped =~ tr/r/t/;

is($mmaped, $slurped, "Translated");
}

{
ok(map_anonymous(my $mmap, 4096), "mapped an anonymous piece of memory");

}
