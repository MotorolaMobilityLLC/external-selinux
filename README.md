SELinux Userspace
=================

Please submit all bug reports and patches to <selinux@vger.kernel.org>.

Subscribe by sending "subscribe selinux" in the body of an email
to <majordomo@vger.kernel.org>.

Installation
------------

Build dependencies on Fedora:

    yum install audit-libs-devel bison bzip2-devel dbus-devel dbus-glib-devel flex flex-devel flex-static glib2-devel libcap-devel libcap-ng-devel pam-devel pcre-devel python3-devel python3-setools swig xmlto redhat-rpm-config


To build and install everything under a private directory, run:

    make DESTDIR=~/obj install install-pywrap

To install as the default system libraries and binaries
(overwriting any previously installed ones - dangerous!),
on x86_64, run:

    make LIBDIR=/usr/lib64 SHLIBDIR=/lib64 install install-pywrap relabel

or on x86 (32-bit), run:

    make install install-pywrap relabel

This may render your system unusable if the upstream SELinux userspace
lacks library functions or other dependencies relied upon by your
distribution.  If it breaks, you get to keep both pieces.

To install libsepol on macOS (mainly for policy analysis):

    cd libsepol; make PREFIX=/usr/local install

This requires GNU coreutils:

    brew install coreutils
