package File::Map;

# This software is copyright (c) 2008, 2009, 2010 by Leon Timmermans <leont@cpan.org>.
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as perl itself.

use 5.008;
use strict;
use warnings FATAL => 'all';

use Exporter 5.57 'import';
use XSLoader;
use Carp qw/croak/;
use Readonly 1.03;

our (@EXPORT_OK, %EXPORT_TAGS);

BEGIN {
	our $VERSION = '0.24';

	XSLoader::load('File::Map', $VERSION);
}

my %export_data = (
	'map'  => [qw/map_handle map_file map_anonymous unmap sys_map/],
	extra  => [qw/remap sync pin unpin advise protect/],
	'lock' => [qw/wait_until notify broadcast lock_map/],
);

while (my ($category, $functions) = each %export_data) {
	for my $function (grep { defined &{$_} } @{$functions}) {
		push @EXPORT_OK, $function;
		push @{ $EXPORT_TAGS{$category} }, $function;
	}
}

@{ $EXPORT_TAGS{all} } = @EXPORT_OK;

Readonly our %PROTECTION_FOR => (
	'<'  => PROT_READ,
	'+<' => PROT_READ | PROT_WRITE,
	'>'  => PROT_WRITE,
	'+>' => PROT_READ | PROT_WRITE,
);

Readonly my $ANON_FH, -1;

## no critic (Subroutines::RequireArgUnpacking)

sub map_handle {
	my (undef, $fh, $mode, $offset, $length) = @_;
	$offset ||= 0;
	$length ||= (-s $fh) - $offset;
	_mmap_impl($_[0], $length, $PROTECTION_FOR{ $mode || '<' }, MAP_SHARED | MAP_FILE, fileno $fh, $offset);
	return;
}

sub map_file {
	my (undef, $filename, $mode, $offset, $length) = @_;
	$mode   ||= '<';
	$offset ||= 0;
	open my $fh, $mode, $filename or croak "Couldn't open file $filename: $!";
	$length ||= (-s $fh) - $offset;
	_mmap_impl($_[0], $length, $PROTECTION_FOR{$mode}, MAP_SHARED | MAP_FILE, fileno $fh, $offset);
	close $fh or croak "Couldn't close $filename after mapping: $!";
	return;
}

sub map_anonymous {
	my (undef, $length) = @_;
	croak 'Zero length specified for anonymous map' if $length == 0;
	_mmap_impl($_[0], $length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, $ANON_FH, 0);
	return;
}

sub sys_map {    ## no critic (ProhibitManyArgs)
	my (undef, $length, $protection, $flags, $fh, $offset) = @_;
	my $fd = ($flags & MAP_ANONYMOUS) ? $ANON_FH : $fh;
	$offset ||= 0;
	_mmap_impl($_[0], $length, $protection, $flags, $fd, $offset);
	return;
}

1;

__END__

=head1 NAME

File::Map - Memory mapping made simple and safe.

=head1 VERSION

Version 0.24

=head1 SYNOPSIS

 use File::Map 'map_file';
 
 map_file my $map, $filename;
 if ($map ne "foobar") {
     $map =~ s/bar/quz/g;
     substr $map, 1024, 11, "Hello world";
 }

=head1 DESCRIPTION

File::Map maps files or anonymous memory into perl variables.

=head2 Advantages of memory mapping

=over 4

=item * Unlike normal perl variables, mapped memory is shared between threads or forked processes.

=item * It is an efficient way to slurp an entire file. Unlike for example L<File::Slurp>, this module returns almost immediately, loading the pages lazily on access. This means you only 'pay' for the parts of the file you actually use.

=item * Perl usually doesn't return memory to the system while running, mapped memory can be returned.

=back

=head2 Advantages of this module over other similar modules

=over 4

=item * Safety and Speed

This module is safe yet fast. Alternatives are either fast but can cause segfaults or loose the mapping when not used correctly, or are safe but rather slow. File::Map is as fast as a normal string yet safe.

=item * Simplicity

It offers a simple interface targeted at common usage patterns

=over 4

=item * Files are mapped into a variable that can be read just like any other variable, and it can be written to using standard Perl techniques such as regexps and C<substr>.

=item * Files can be mapped using a set of simple functions. There is no need to know weird constants or the order of 6 arguments.

=item * It will automatically unmap the file when the scalar gets destroyed. This works correctly even in multi-threaded programs.

=back

=item * Portability

File::Map supports Unix, VMS and Windows.

=item * Thread synchronization

It has built-in support for thread synchronization.

=back

=head1 FUNCTIONS

=head2 Mapping

The following functions for mapping a variable are available for exportation.

=over 4

=item * map_handle $lvalue, $filehandle, $mode = '<', $offset = 0, $length = -s(*handle) - $offset

Use a filehandle to map into an lvalue. $filehandle should be a scalar filehandle. $mode uses the same format as C<open> does (it currently accepts C<< < >>, C<< +< >>, C<< > >> and C<< +> >>). $offset and $length are byte positions in the file, and default to mapping the whole file.

=item * map_file $lvalue, $filename, $mode = '<', $offset = 0, $length = -s($filename) - $offset

Open a file and map it into an lvalue. Other than $filename, all arguments work as in map_handle.

=item * map_anonymous $lvalue, $length

Map an anonymous piece of memory.

=item * sys_map $lvalue, $length, $protection, $flags, $filehandle, $offset = 0

Low level map operation. It accepts the same constants as mmap does (except its first argument obviously). If you don't know how mmap works you probably shouldn't be using this.

=item * unmap $lvalue

Unmap a variable. Note that normally this is not necessary as variables are unmapped automatically at destruction, but it is included for completeness.

=item * remap $lvalue, $new_size

Try to remap $lvalue to a new size. It may fail if there is not sufficient space to expand a mapping at its current location. This call is linux specific and not supported on other systems.

=back

=head2 Auxiliary  

=over 4

=item * sync $lvalue, $synchronous = 1

Flush changes made to the memory map back to disk. Mappings are always flushed when unmapped, so this is usually not necessary. If $synchronous is true and your operating system supports it, the flushing will be done synchronously.

=item * pin $lvalue

Disable paging for this map, thus locking it in physical memory. Depending on your operating system there may be limits on pinning.

=item * unpin $lvalue

Unlock the map from physical memory.

=item * advise $lvalue, $advice

Advise a certain memory usage pattern. This is not implemented on all operating systems, and may be a no-op. The following values for $advice are always accepted:.

=over 2

=item * normal

Specifies that the application has no advice to give on its behavior with respect to the mapped variable. It is the default characteristic if no advice is given.

=item * random

Specifies that the application expects to access the mapped variable in a random order.

=item * sequential

Specifies that the application expects to access the mapped variable sequentially from start to end.

=item * willneed

Specifies that the application expects to access the mapped variable in the near future.

=item * dontneed

Specifies that the application expects that it will not access the mapped variable in the near future.

=back

On some systems there may be more values available, but this can not be relied on. Unknown values for $advice will cause a warning but are further ignored.

=item * protect $lvalue, $mode

Change the memory protection of the mapping. $mode takes the same format as, but also accepts sys_map style constants.

=back

=head2 Locking

These locking functions provide locking for threads for the mapped region. The mapped region has an internal lock and condition variable. The condition variable functions(C<wait_until>, C<notify>, C<broadcast>) can only be used inside a locked block. If your perl has been compiled without thread support the condition functions will not be available.

=over 4

=item * lock_map $lvalue

Lock $lvalue until the end of the scope. If your perl does not support threads, this will be a no-op.

=item * wait_until { block } $lvalue

Wait for block to become true. After every failed attempt, wait for a signal. It returns the value returned by the block.

=item * notify $lvalue

This will signal to one listener that the map is available.

=item * broadcast $lvalue

This will signal to all listeners that the map is available.

=back

=head2 CONSTANTS

=over 4

=item PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE, MAP_ANON, MAP_FILE

These constants are used for sys_map. If you think you need them your mmap manpage will explain them, but in most cases you can skip sys_map altogether.

=back

=head1 EXPORTS

All previously mentioned functions are available for exportation, but none are exported by default. Some functions may not be available on your OS or your version of perl as specified above. A number of tags are defined to make importation easier.

=over 4

=item * :map

map_handle, map_file, map_anonymous, sys_map, unmap

=item * :extra

remap, sync, pin, unpin, advise

=item * :lock

lock_map, wait_until, notify, broadcast

=item * :constants

PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE, MAP_ANON, MAP_FILE

=item * :all

All functions defined in this module.

=back

=head1 DIAGNOSTICS

In this overview %f is the name of the function that produced the error, and %e is some error from your OS.

=head2 Exceptions

=over 4

=item * Could not %f: this variable is not memory mapped

An attempt was made to C<sync>, C<remap>, C<unmap>, C<pin>, C<unpin>, C<advise> or C<lock_map> an unmapped variable.

=item * Could not %f: %e

Your OS didn't allow File::Map to do what you asked it to do for the reason specified in %e.

=item * Trying to %f on an unlocked map

You tried to C<wait_until>, C<notify> or C<broadcast> on an unlocked variable.

=item * Zero length not allowed for anonymous map

A zero length anonymous map is not possible (or in any way useful).

=item * Can't remap a shared mapping

An attempts was made to remap a mapping that is shared among different threads, this is not possible.

=back

=head2 Warnings

=over 4

=item * Writing directly to a to a memory mapped file is not recommended

Due to the way perl works internally, it's not possible to write a mapping implementation that allows direct assignment yet performs well. As a compromise, File::Map is capable of fixing up the mess if you do it nonetheless, but it will warn you that you're doing something you shouldn't. This warning is only given when C<use warnings 'substr'> is in effect.

=item * Truncating new value to size of the memory map

This warning is additional to the previous one, warning you that you're losing data. This warning is only given when C<use warnings 'substr'> is in effect.

=item * Unknown advice '%s'

You gave advise an advice it didn't know. This is probably either a typo or a portability issue. This warning is only given when C<use warnings 'portable'> is in effect.

=item * Syncing a readonly map makes no sense

C<sync> flushes changes to the map to the filesystem. This obviously is of little use when you can't change the map. This warning is only given when C<use warnings 'io'> is in effect.

=item * Can't overwrite an empty map

Overwriting an empty map is rather nonsensical, hence a warning is given when this is tried. This warning is only given when C<use warnings 'substr'> is in effect.

=back

=head1 DEPENDENCIES

This module does not have any dependencies on non-standard modules.

=head1 PITFALLS

On perl versions lower than 5.11.5 many string functions are limited to L<32bit logic|http://rt.perl.org/rt3//Public/Bug/Display.html?id=62646>, even on 64bit architectures. Effectively this means you can't use them on strings bigger than 2GB. If you need to do this, I can only recommend upgrading to 5.12.

You probably don't want to use C<E<gt>> as a mode. This does not give you reading permissions on many architectures, resulting in segmentation faults when trying to read a variable (confusingly, it will work on some others like x86).

=head1 BUGS AND LIMITATIONS

As any piece of software, bugs are likely to exist here. Bug reports are welcome.

Please report any bugs or feature requests to C<bug-file-map at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=File-Map>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SEE ALSO

=over 4

=item * L<Sys::Mmap>, the original Perl mmap module

=item * L<IPC::Mmap>, another mmap module

=item * L<mmap(2)>, your mmap man page

=item * L<Win32::MMF>

=item * CreateFileMapping at MSDN: L<http://msdn.microsoft.com/en-us/library/aa366537(VS.85).aspx>

=back

=head1 AUTHOR

Leon Timmermans, C<< <leont at cpan.org> >>

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc File::Map

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=File-Map>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/File-Map>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/File-Map>

=item * Search CPAN

L<http://search.cpan.org/dist/File-Map>

=back

=head1 COPYRIGHT AND LICENSE

Copyright 2008, 2009, 2010 Leon Timmermans, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as perl itself.
