Key management for kerberos service principals
==============================================

This software allows for automatic rekeying of kerberos service princpals<sup id="serviceref">[1](#servicefootnote)</sup>,
even if they are shared. It also includes functionality for initial
keying (or key resets) of non-shared principals with random keys.

The software attempts to achieve perfect forward secrecy by encrypting
with TLS (DH or ECDH. RSA ciphersuites and server certificates are not used),
and then authenticating the connection using GSSAPI and channel bindings. The
channel bindings do not formally conform to RFC5056, RFC5554, or RFC5929, but
are intended to be equivalent to tls-unique, with each side sending a MIC of
the finished messages obtained from openssl<sup id="tlsuniqueref">[2](#tlsuniquefootnote)</sup>.

There is not any operational documentation beyond the manpage. Please contact
cg2v@andrew.cmu.edu or open an issue if you want help setting this up at your
site.

The LDAP authorzation mechanisms are tailored to specific Carnegie Mellon
LDAP systems and would require adaptation to use elsewhere. There is a simple
file based authorization mechanism that is more general



<b id="whatisaservicefootnote">1</b>: Principals which are used only as servers, and never as clients [↩](#serviceref)

<b id="tlsuniquefootnote">2</b>: Session resumption is disabled, and RSA
ciphersuites were never supported, so this protocol should not be vulnerable to
triple handshake attacks. [↩](#tlsuniqueref)
