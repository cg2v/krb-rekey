# Copyright (c) 2015 Carnegie Mellon University.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer. 
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any other legal
#    details, please contact  
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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


License: CMU
Vendor: Carnegie Mellon University
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
