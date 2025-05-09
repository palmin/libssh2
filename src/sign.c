/* Copyright (C) 2024 Daniel Stenberg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"
#include <stdio.h>

/* Needed for struct iovec on some platforms */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

/*
 * libssh2_sign_with_keydata
 *
 * Signs the given data using a private key loaded from memory.
 *
 * Parameters:
 *   session      - The SSH session
 *   keydata      - Private key data buffer
 *   keydata_len  - Length of private key data
 *   passphrase   - Passphrase for encrypted private key or NULL
 *   datavec      - Number of buffers in data array
 *   data         - Array of data buffers to sign
 *   signature    - Output buffer for the signature (allocated by the function)
 *   signature_len - Length of the signature
 *
 * Returns:
 *   0 on success, negative number on failure
 */
LIBSSH2_API int
libssh2_sign_with_keydata(LIBSSH2_SESSION *session,
                          const char *keydata,
                          size_t keydata_len,
                          const char *passphrase,
                          int datavec,
                          const struct iovec data[],
                          unsigned char **signature,
                          size_t *signature_len)
{
    const LIBSSH2_HOSTKEY_METHOD **hostkey_methods = libssh2_hostkey_methods();
    const LIBSSH2_HOSTKEY_METHOD *method = NULL;
    void *abstract = NULL;
    int rc;
    unsigned char *pubkeydata = NULL;
    size_t pubkeydata_len = 0;
    unsigned char *methodname = NULL;
    size_t methodname_len = 0;

    if(!session || !keydata || !signature || !signature_len || !data) {
        return _libssh2_error(session, LIBSSH2_ERROR_BAD_USE,
                             "Invalid parameters for signing data");
    }

    /* Initialize the signature output parameters */
    *signature = NULL;
    *signature_len = 0;

    /* Use the default SSH public key format detection */
    rc = _libssh2_pub_priv_keyfilememory(session, &methodname, &methodname_len,
                                        &pubkeydata, &pubkeydata_len,
                                        keydata, keydata_len, passphrase);

    if(rc) {
        return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                             "Unable to extract public key from private key data");
    }

    /* Find the appropriate method based on key type */
    for(rc = 0; hostkey_methods[rc]; rc++) {
        if(methodname_len == strlen(hostkey_methods[rc]->name) &&
           memcmp(methodname, hostkey_methods[rc]->name, methodname_len) == 0) {
            method = hostkey_methods[rc];
            break;
        }
    }

    if(!method) {
        LIBSSH2_FREE(session, methodname);
        LIBSSH2_FREE(session, pubkeydata);
        return _libssh2_error(session, LIBSSH2_ERROR_METHOD_NONE,
                             "No suitable private key method found");
    }

    /* Initialize the private key */
    rc = method->initPEMFromMemory(session, keydata, keydata_len,
                                  (const unsigned char *)passphrase, &abstract);
    if(rc) {
        LIBSSH2_FREE(session, methodname);
        LIBSSH2_FREE(session, pubkeydata);
        return _libssh2_error(session, LIBSSH2_ERROR_FILE,
                             "Unable to initialize private key");
    }

    /* Sign the data */
    rc = method->signv(session, signature, signature_len,
                      datavec, data, &abstract);

    /* Clean up */
    if(method->dtor) {
        method->dtor(session, &abstract);
    }

    LIBSSH2_FREE(session, methodname);
    LIBSSH2_FREE(session, pubkeydata);

    return rc;
}

