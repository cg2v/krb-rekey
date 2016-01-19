# Copyright (c) 2015 Carnegie Mellon University
# All Rights Reserved.
# 
# Permission to use, copy, modify and distribute this software and its
# documentation is hereby granted, provided that both the copyright
# notice and this permission notice appear in all copies of the
# software, derivative works or modified versions, and any portions
# thereof, and that both notices appear in supporting documentation.
#
# CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
# CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
# ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
#
# Carnegie Mellon requests users of this software to return to
#
#  Software Distribution Coordinator  or  Software_Distribution@CS.CMU.EDU
#  School of Computer Science
#  Carnegie Mellon University
#  Pittsburgh PA 15213-3890
#
# any improvements or extensions that they make and grant Carnegie Mellon
# the rights to redistribute these changes.

%define vers 006a

%if 0%{?sles_version:1}
%define relsuffix sles%{sles_version}
%define breqs pkg-config
%else
%if 0%{?rhel:1}
%define relsuffix EL%{rhel}
%define breqs pkgconfig
%endif
%endif


Name: rekey
Summary: Automatic Kerberos rekey management
Group: System/Management
Version: %{vers}
Source: %{name}-%{vers}.tar.gz
Release: 1%{?relsuffix:.%{relsuffix}}
BuildRequires: autoconf, automake, krb5-devel, perl, %{breqs}
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root


License: CMUCS
Vendor: Carnegie Mellon SCS Facilities
Packager: Facilities Help <help+@cs.cmu.edu>
%if 0%{?sles_version:1}
Distribution: SUSE Linux Enterprise %{sles_version}
%else
%if 0%{?rhel:1}
Distribution: EL
%endif
%endif

%ifarch i386
BuildArch: i686
%endif

%description
The rekey service coordinates automatic rekeying of Kerberos principals,
including those whose keys are shared across multiple hosts.  This package
contains clients for managing the rekey process and downloading new keys.


%prep
%setup -q -c -n %{name}-%{version}

%build
./autogen %{vers}
%configure --with-default-service-principal=rekey/daemon@CS.CMU.EDU
%{__make}

%install
%{__rm} -rf %{buildroot}
%{__make} install DESTDIR=%{buildroot}
%{__rm} -f %{buildroot}%{_mandir}/man8/rekeysrv.*

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root)
%{_bindir}/rekeymgr
%{_sbindir}/age_keytab
%{_sbindir}/getnewkeys
%doc %{_mandir}/man1/rekeymgr.*
%doc %{_mandir}/man8/age_keytab.*
%doc %{_mandir}/man8/getnewkeys.*
