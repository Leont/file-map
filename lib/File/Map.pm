package File::Map;

# This software is copyright (c) 2008, 2009 by Leon Timmermans <leont@cpan.org>.
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as perl itself.

use 5.007003;
use strict;
use warnings;

use base qw/Exporter DynaLoader/;
use Symbol qw/qualify_to_ref/;
use Carp qw/croak/;

our $VERSION = '0.14';

our (@EXPORT_OK, %EXPORT_TAGS, %MAP_CONSTANTS);

bootstrap File::Map $VERSION;

while (my ($name, $value) = each %MAP_CONSTANTS) {
	no strict 'refs';
	*{$name} = sub { return $value };
	push @EXPORT_OK, $name;
	push @{ $EXPORT_TAGS{constants} }, $name;
}

my %export_data = (
	'map'  => [qw/map_handle map_file map_anonymous unmap sys_map/],
	extra  => [qw/remap sync pin unpin advise page_size/],
	'lock' => [qw/locked wait_until notify broadcast lock_map/],
);

while (my ($category, $functions) = each %export_data) {
	for my $function (grep { defined &{$_} } @{$functions}) {
		push @EXPORT_OK, $function;
		push @{ $EXPORT_TAGS{$category} }, $function;
	}
}

my %protection_for = (
	'<'  => $MAP_CONSTANTS{PROT_READ},
	'+<' => $MAP_CONSTANTS{PROT_READ} | $MAP_CONSTANTS{PROT_WRITE},
	'>'  => $MAP_CONSTANTS{PROT_WRITE},
	'+>' => $MAP_CONSTANTS{PROT_READ} | $MAP_CONSTANTS{PROT_WRITE},
);

## no critic ProhibitSubroutinePrototypes

#These must be defined before sys_map to ignore its prototype

sub map_handle(\$*@) {
	my ($var_ref, $glob, $mode, $offset, $length) = @_;
	my $fh = qualify_to_ref($glob, caller);
	$offset ||= 0;
	$length ||= (-s $fh) - $offset;
	return sys_map($var_ref, $length, $protection_for{ $mode || '<' }, $MAP_CONSTANTS{MAP_SHARED} | $MAP_CONSTANTS{MAP_FILE}, $fh, $offset);
}

sub map_file(\$@) {
	my ($var_ref, $filename, $mode, $offset, $length) = @_;
	$mode   ||= '<';
	$offset ||= 0;
	open my $fh, $mode, $filename or croak "Couldn't open file $filename: $!";
	$length ||= (-s $fh) - $offset;
	my $ret = sys_map($var_ref, $length, $protection_for{$mode}, $MAP_CONSTANTS{MAP_SHARED} | $MAP_CONSTANTS{MAP_FILE}, $fh, $offset);
	close $fh or croak "Couldn't close $filename: $!";
	return $ret;
}

sub map_anonymous(\$@) {
	my ($var_ref, $length) = @_;
	croak 'Zero length specified for anonymous map' if $length == 0;
	return sys_map($var_ref, $length, $MAP_CONSTANTS{PROT_READ} | $MAP_CONSTANTS{PROT_WRITE}, $MAP_CONSTANTS{MAP_ANONYMOUS} | $MAP_CONSTANTS{MAP_SHARED});
}

sub sys_map(\$$$$*;$) {    ## no critic ProhibitManyArgs
	my ($var_ref, $length, $protection, $flags, $glob, $offset) = @_;
	my $fd = $flags & $MAP_CONSTANTS{MAP_ANONYMOUS} ? -1 : fileno qualify_to_ref($glob, caller);
	$offset ||= 0;
	return eval { _mmap_impl($var_ref, $length, $protection, $flags, $fd, $offset) } || do {
		$@ =~ s/\n\z//mx;
		croak $@;
	};
}

1;

__END__

=head1 NAME

File::Map - Memory mapping made simple and safe.

=head1 VERSION

Version 0.14

=head1 SYNOPSIS

 use File::Map ':map';
 
 map_file my $mmap, $filename;
 if ($mmap ne "foobar") {
     $mmap =~ s/bar/quz/g;
 }

=head1 DESCRIPTION

File::Map maps files or anonymous memory into perl variables.

=head2 Advantages of memory mapping

=over 4

=item * Unlike normal perl variables, mapped memory is shared between threads or forked processes.

=item * It is an efficient way to slurp an entire file. Unlike for example L<File::Slurp>, this module returns almost immediately, loading the pages lazily on access. This means you only 'pay' for the parts of the file you actually use.

=item * Perl normally never returns memory to the system while running, mapped memory can be returned.

=back

=head2 Advantages of this module over other similar modules

=over 4

=item * Safety and Speed

This module is safe yet fast. Alternatives are either fast but can cause segfaults or loose the mapping when not used correctly, or are safe but rather slow. File::Map is as fast as a normal string yet safe.

=item * Simplicity

It offers a simple interface targeted at common usage patterns

=over 4

=item * Files are mapped into a variable that can be read just like any other variable, and it can be written to using standard Perl techniques such as regexps and C<substr>.

=item * Files can be mapped using a set of simple functions. There is no need to know weird constants or 6 arguments.

=item * It will automatically unmap the file when the scalar gets destroyed. This works correctly even in multi-threaded programs.

=back

=item * Portability

File::Map supports both POSIX systems and Windows.

=item * Thread synchronization

It has built-in support for thread synchronization. 

=back

=head1 FUNCTIONS

=head2 Mapping

The following functions for mapping a variable are available for exportation. They all take an lvalue as their first argument, except page_size.

=over 4

=item * map_handle $lvalue, *filehandle, $mode = '<', $offset = 0, $length = -s(*handle) - $offset

Use a filehandle to mmap into an lvalue. *filehandle may be a bareword, constant, scalar expression, typeglob, or a reference to a typeglob. $mode uses the same format as C<open> does. $offset and $length are byte positions in the file, and default to mapping the whole file.

=item * map_file $lvalue, $filename, $mode = '<', $offset = 0, $length = -s($filename) - $offset

Open a file and mmap it into an lvalue. Other than $filename, all arguments work as in map_handle.

=item * map_anonymous $lvalue, $length

Map an anonymous piece of memory.

=item * sys_map $lvalue, $length, $protection, $flags, *filehandle, $offset = 0

Low level map operation. It accepts the same constants as mmap does (except its first argument obviously). If you don't know how mmap works you probably shouldn't be using this.

=item * sync $lvalue, $synchronous = 1

Flush changes made to the memory map back to disk. Mappings are always flushed when unmapped, so this is usually not necessary. If $synchronous is true and your operating system supports it, the flushing will be done synchronously.

=item * remap $lvalue, $new_size

Try to remap $lvalue to a new size. It may fail if there is not sufficient space to expand a mapping at its current location. This call is linux specific and currently not supported on other systems.

=item * unmap $lvalue

Unmap a variable. Note that normally this is not necessary, but it is included for completeness.

=item * pin $lvalue

Disable paging for this map, thus locking it in physical memory. Depending on your operating system there may be limits on pinning.

=item * unpin $lvalue

Unlock the map from physical memory.

=item * advise $lvalue, $advice

Advise a certain memory usage pattern. This is not implemented on all operating systems, and may be a no-op. $advice is a string with one of the following values.

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

=back

=head2 Locking

These locking functions provide locking for threads for the mapped region. The mapped region has an internal lock and condition variable. The condition variable functions(C<wait_until>, C<notify>, C<broadcast>) can only be used inside a locked block. If your perl has been compiled without thread support the condition functions will not be available.

=over 4

=item * lock_map $lvalue

Lock $lvalue until the end of the scope. If your perl does not support threads, this will be a no-op.

=item * wait_until { block } $lvalue

Wait for block to become true. After every failed try, wait for a signal. It returns the value returned by the block.

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

locked, wait_until, notify, broadcast

=item * :constants

PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE, MAP_ANON, MAP_FILE

=back

=head1 DIAGNOSTICS

If you C<use warnings>, this module will give warnings if the variable is improperly used (anything that changes its size). This can be turned off lexically by using C<no warnings 'substr'>.

If an error occurs in any of these functions, an exception will be thrown. In particular; trying to C<sync>, C<remap>, C<unmap>, C<pin>, C<unpin>, C<advise> or C<lock_map> a variable that hasn't been mapped will cause an exception to be thrown.

=head1 DEPENDENCIES

This module does not have any dependencies on non-standard modules.

=head1 PITFALLS

You probably don't want to use C<E<gt>> as a mode. This does not give you reading permissions on many architectures, resulting in segmentation faults (confusingly, it will work on some others).

=head1 BUGS AND LIMITATIONS

As any piece of software, bugs are likely to exist here. Bug reports are welcome.

Please report any bugs or feature requests to C<bug-sys-mmap-simple at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=File-Map>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SEE ALSO

=over 4

=item * L<Sys::Mmap>, the original Perl mmap module

=item * L<IPC::Mmap>, another mmap module

=item * L<mmap(2)>, your mmap man page

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

Copyright 2008, 2009 Leon Timmermans, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as perl itself.
