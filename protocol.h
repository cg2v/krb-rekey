/*
 * Copyright (c) 2008-2009 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
#ifndef HEADER_PROTOCOL
#define HEADER_PROTOCOL
/* data exchanges are TLV, with 8 bit tag & 32 bit length */


/* perform a gss authentication step */
#define OP_AUTH 1 
/* data is flags, gss context token 
   4 bytes of flags
   4 bytes of length
   N bytes of gss context token
*/
/* report a gss authentication error (with error token) */
#define OP_AUTHERR 2
/* data is gss error token */
/* disconnect immediately after this */

/* send signed channel binding data */
#define OP_AUTHCHAN 3
/* data is mic over:
   4 bytes of local finished message length
   N bytes of local finished message
   4 bytes of remote finished message length
   N bytes of remote finished message
*/

/* start a new rekey for a shared principal */
/* requires admin authorization */
#define OP_NEWREQ 4
/* data is principal name, flag word,
   followed by list of hostnames (i.e. host instances),
   of authorized recipients:
  4 bytes of principal name length
  N bytes of principal name
  4 bytes of flags
  4 bytes of access list count {
    4 bytes of hostname length
    N bytes of hostname
  }
*/
/* get the status of an in-progress rekey */
/* requires admin authorization */
#define OP_STATUS 5
/* data is principal name
  4 bytes of principal name length
  N bytes of principal name
*/
/* fetch the new keys this host is supposed to get */
/* requires host authorization */
#define OP_GETKEYS 6
/* optional data is a list of principals
   4 bytes of principal count {
     4 bytes of principal name length
     N bytes of principal
   }
*/

/* inform the server that a particular keyset has been
   written to a keytab */
/* requires host, admin, or target authorization */
#define OP_COMMITKEY 7
/* Data is principal name, kvno 
   4 bytes of principal name length
   N bytes of principal name
   4 bytes of kvno
*/
/* rekey a non-shared principal */
/* requires admin or target authorization */
#define OP_SIMPLEKEY 8
/* data is principal name 
   4 bytes of principal name length
   N bytes of principal name
   4 bytes of flags
*/
/* abort an in-progress rekey */
/* requires admin or target authorization */
#define OP_ABORTREQ 9
/* data is principal name
  4 bytes of principal name length
  N bytes of principal name
*/

/* finalize (complete) an in-progress rekey */
/* There must not be any hosts which have not yet commited */
/* requires admin or target authorization */
#define OP_FINALIZE 10
/* data is principal name
  4 bytes of principal name length
  N bytes of principal name
*/
/* delete a principal that does not have an in-progress rekey */
/* requires admin authorization */
#define OP_DELPRINC 11
/* data is principal name
  4 bytes of principal name length
  N bytes of principal name
*/

#define MAX_OPCODE OP_DELPRINC

#define RESP_AUTH 128
/* data is flags, gss context token
   4 bytes of flags
   4 bytes of length
   N bytes of gss context token
*/
#define RESP_AUTHERR 129
/* data is gss error token */
#define RESP_AUTHCHAN 130
/* data is mic over
   4 bytes of local finished message length
   N bytes of local finished message
   4 bytes of remote finished message length
   N bytes of remote finished message
*/
#define RESP_ERR 131
/* data is error code, error string 
   4 bytes of error code
   4 bytes of error string length
   N bytes of error string 
*/
#define RESP_FATAL 132
/* data is error code, error string 
   4 bytes of error code
   4 bytes of error string length
   N bytes of error string 
*/

#define RESP_OK 133
/* No data */

#define RESP_STATUS 134
/* data is flags, status of each authorized client 
   4 bytes of flags
   4 bytes of kvno
   4 bytes of access list count {
     4 bytes of per-entry flags
     4 bytes of hostname length
     N bytes of hostname 
   } 
*/
#define RESP_KEYS 135
/* data is list of key entries (principal name, kvno, enctype, key 
   4 bytes of principal count {
     4 bytes of principal name length
     N bytes of principal
     4 bytes of kvno
     4 bytes of key count {
       4 bytes of enctype
       4 bytes of key length
       N bytes of key
     }
   }
*/
   /* COMMITKEY returns RESP_OK on success */
   /* SIMPLEKEY returns RESP_KEYS on success */
   /* ABORTREQ returns RESP_OK on success */
   /* FINALIZE returns RESP_OK on success */


   /* more auth packets are expected */
#define AUTHFLAG_MORE 0x1

   /* only create des keys for this principal */
#define REQFLAG_DESONLY 0x1
   /* do not create des keys for this principal */
#define REQFLAG_NODES 0x2
   /* do not create post-1510 enctypes for this principal */
#define REQFLAG_COMPAT_ENCTYPE 0x4
#define REQFLAG_MASK 0x7

  /* this host has commited the key */
#define STATUSFLAG_COMPLETE 0x1
  /* this host has picked up the key */
#define STATUSFLAG_ATTEMPTED 0x2

   /* authentication failed */
#define ERR_AUTHN 1
   /* not authorized */
#define ERR_AUTHZ 2
   /* bad/unknown request type */
#define ERR_BADOP 3
   /* request not properly formatted */
#define ERR_BADREQ 4
   /* no keys for you */
#define ERR_NOKEYS 5
   /* no matching key/request found */
#define ERR_NOTFOUND 6
   /* Other/unknown error */
#define ERR_OTHER 7

#endif
