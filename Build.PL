use 5.007003;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
	module_name        => 'File::Map',
	license            => 'perl',
	dist_author        => 'Leon Timmermans <leont@cpan.org>',
	dist_version_from  => 'lib/File/Map.pm',
	configure_requires => {
		'Module::Build' => 0,
	},
	build_requires => {
		'ExtUtils::CBuilder' => 0,
		'Module::Build'=> 0,
		'IO::Handle'   => 0,
		'Test::Exception' => 0,
		'Test::More'   => 0,
		'Test::Warn'   => 0,
		'Test::NoWarnings' => 0,
		'Time::HiRes'  => 0,
	},
	requires => {
		perl           => 5.008,
		'Const::Fast'  => 0,
		'Sub::Exporter'=> 0,
		'PerlIO::Layers' => 0.007,
	},
	suggests => {
		perl           => 5.012,
	},
	meta_merge => {
		resources      => {
			bugtracker => 'http://rt.cpan.org/NoAuth/Bugs.html?Dist=File-Map',
			repository => 'http://github.com/Leont/file-map/tree',
		},
		keywords       => [ 'mmap', 'memory mapping' ],
	},
	add_to_cleanup     => ['File-Map-*'],
	create_makefile_pl => 'small',
	sign               => 1,
);

$builder->create_build_script();
