#!perl

use strict;
use warnings;
use Sys::Mmap::Simple qw/map_handle map_file map_anonymous sync locked unmap/;
use IO::Handle;
use Test::More tests => 20;

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
ok(map_handle(my $mmaped, $copy, '>'), "map succeeded");
ok(defined $mmaped,                  "mmaped is defined");
ok( length $mmaped > 300,            "length of mmaped is big enough");
is($mmaped, $slurped,                "slurped is mmaped");

s/e/a/g for ($mmaped, $slurped);

is($mmaped, $slurped, "slurped is mmaped after translation");

locked { is($_, $slurped, '$_ == $slurped') } $mmaped;

locked { tr/r/t/ }  $mmaped;
$slurped =~ tr/r/t/;

is($mmaped, $slurped, "Translated");

{
my $warned = 0;
local $SIG{__WARN__} = sub { $warned = 1 if $_[0] =~ /^Writing directly to a to a memory mapped file is not recommended at / };
$mmaped = reverse $mmaped;

ok($warned, 'reversing should give a warning');
}

is($mmaped, scalar reverse($slurped), "mmap is reversed");

$mmaped = $mmaped;
}
