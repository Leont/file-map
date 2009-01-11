use 5.007003;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
	module_name        => 'Sys::Mmap::Simple',
	license            => 'perl',
	dist_author        => 'Leon Timmermans <leont@cpan.org>',
	dist_version_from  => 'lib/Sys/Mmap/Simple.pm',
	build_requires => {
		perl           => 5.007003,
		'Module::Build'=> 0,
		'Test::More'   => 0,
		'IO::Handle'   => 0,
		threads        => 0,
		'ExtUtils::CBuilder' => 0,
	},
	add_to_cleanup     => ['Sys-Mmap-Simple-*'],
	create_makefile_pl => 'small',
);

$builder->create_build_script();
