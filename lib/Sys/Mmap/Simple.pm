package Sys::Mmap::Simple;

use 5.007003;
use strict;
use warnings;

use base qw/Exporter DynaLoader/;
use Symbol qw/qualify_to_ref/;
use Carp qw/croak/;

our $VERSION = '0.06';

our (@EXPORT_OK, %EXPORT_TAGS);

bootstrap Sys::Mmap::Simple $VERSION;

my %export_data = (
	MAP       => [qw/map_handle map_file map_anonymous remap unmap/],
	EXTRA     => [qw/sync locked/],
	CONDITION => [qw/condition_wait condition_signal condition_broadcast/],
);

while (my ($category, $values) = each %export_data) {
	for my $function (grep { defined &{$_} } @{$values}) {
		push @EXPORT_OK, $function;
		push @{ $EXPORT_TAGS{$category} }, $function;
	}
}

sub map_handle(\$*@) {
	my ($var_ref, $glob, $writable) = @_;
	my $fh = qualify_to_ref($glob, caller);
	return _mmap_wrapper($var_ref, -s $fh, defined $writable ? $writable : 0, fileno $fh);
}

sub map_file(\$@) {
	my ($var_ref, $filename, $writable) = @_;
	my $mode = $writable ? '+<' : '<';
	open my $fh, $mode, $filename or croak "Couldn't open file $filename: $!";
	my $ret = _mmap_wrapper($var_ref, -s $fh, defined $writable ? $writable : 0, fileno $fh);
	close $fh or croak "Couldn't close $filename: $!";
	return $ret;
}

sub _mmap_wrapper {
	my $ret;
	eval { $ret = _mmap_impl(@_) };
	if ($@) {
		$@ =~ s/\n$//mx;
		croak $@;
	}
	return $ret;
}

1;

__END__

=head1 NAME

Sys::Mmap::Simple - Memory mapping made simple and safe.

=head1 VERSION

Version 0.03

=head1 SYNOPSIS

 use Sys::Mmap::Simple 'map_file';
 
 map_file my $mmap, $filename;
 if ($mmap eq "foobar") {
     $mmap =~ s/bar/quz/g;
 }

=head1 DESCRIPTION

Sys::Mmap::Simple maps files or anonymous memory into perl variables.

=head2 Advantages of memory mapping

=over 4

=item Unlike normal perl variables, mapped memory is shared between threads or forked processes.

=item It is an efficient way to slurp an entire file. Unlike for example L<File::Slurp>, this module returns almost immediately, loading the pages lazily on access. This means you only 'pay' for the parts of the file you actually use.

=item Perl normally never returns memory to the system while running, mapped memory can be returned.

=back

=head2 Advantages of this module over other similar modules

=head3 Safety and Speed

This module is safe yet fast. Alternatives are either fast but can cause segfaults or loose the mapping when not used correctly, or are safe but rather slow (due to ties). Sys::Mmap::Simple is as fast as a normal string yet safe.

=head3 Simplicity

It offers a more simple interface targeted at common usage patterns

=over 4

=item Files are mapped into a variable that can be read just like any other variable, and it can be written to using standard Perl techniques such as regexps and C<substr>.

=item Files can be mapped using a set of simple functions. No weird constants or 6 argument functions.

=item It will automatically unmap the file when the scalar gets destroyed. This works correctly even in multithreaded programs.

=back

=head3 Portability

Sys::Mmap::Simple supports both Unix and Windows.

=head3 Thread synchronization

It has built-in support for thread synchronization. 

=head1 FUNCTIONS

=head2 Mapping

The following functions for mapping a variable are available for exportation. They all take an lvalue as their first argument.

=head3 map_handle $variable, *handle, $writable = 0

Use a filehandle to mmap into a variable. *handle may be filehandle or a reference to a filehandle.

=head3 map_file $variable, $filename, $writable = 0

Open a file and mmap it into a variable.

=head3 map_anonymous $variable, $length

Map an anonymous piece of memory.

=head3 sync $variable

Flush changes made to the memory map back to disk. Mappings are always flushed when unmapped, so this is usually not necessary. If your operating system supports it, the flushing will be done synchronously.

=head3 remap $variable, $new_size

Try to remap $variable to a new size. It may fail if there is not sufficient space to expand a mapping at its current location. This call is linux specific and currently not supported or even defined on other systems.

=head3 unmap $variable

Unmap a variable. Note that normally this is not necessary, but it is included for completeness.

=head2 Locking

These locking functions provide thread based locking for the mapped region. The mapped region has an internal lock and condition variable. The condional functions can only be used in a locked block. If your perl has been compiled without thread support the condition functions will not be availible, and C<locked> will execute its block without locking.

=head3 locked { block } $variable

Perform an action while keeping a thread lock on the map. The map is accessible as C<$_>. It will return whatever its block returns.

=head3 condition_wait { block }

Wait for block to become true. After every failed try, wait for a signal. It returns the value returned by the block.

=head3 condition_signal

This will signal to one listener that the map is available.

=head3 condition_broadcast

This will signal to all listeners that the map is available.

=head1 DIAGNOSTICS

If you C<use warnings>, this module will give warnings if the variable is improperly used (anything that changes its size). This can be turned off lexically by using C<no warnings 'substr'>.

Trying to sync, remap, unmap or lock a variable that hasn't been mapped will cause an exception to be thrown.

=head1 DEPENDENCIES

This module does not have any dependencies on other modules.

=head1 BUGS AND LIMITATIONS

This is an early release. Bugs are likely. Bug reports are welcome.

Please report any bugs or feature requests to C<bug-sys-mmap-simple at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Sys-Mmap-Simple>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SEE ALSO

=over 4

=item L<Sys::Mmap>, the original Perl mmap module.

=item L<IPC::Mmap>, Another mmap module.

=back

=head1 AUTHOR

Leon Timmermans, C<< <leont at cpan.org> >>

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Sys::Mmap::Simple

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Sys-Mmap-Simple>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Sys-Mmap-Simple>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Sys-Mmap-Simple>

=item * Search CPAN

L<http://search.cpan.org/dist/Sys-Mmap-Simple>

=back

=head1 COPYRIGHT AND LICENSE

Copyright 2008 Leon Timmermans, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as perl itself.
