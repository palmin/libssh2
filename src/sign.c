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
 * Returns a complete agent signing blob including algorithm name and lengths.
 *
 * Parameters:
 *   session      - The SSH session
 *   keydata      - Private key data buffer
 *   keydata_len  - Length of private key data
 *   passphrase   - Passphrase for encrypted private key or NULL
 *   datavec      - Number of buffers in data array
 *   data         - Array of data buffers to sign
 *   signature    - Output buffer for the signature blob (allocated by the function)
 *   signature_len - Length of the entire signature blob
 *   flags        - Flags for RSA signing method:
 *                  0x00: Use ssh-rsa (default)
 *                  0x02: Use rsa-sha2-256
 *                  0x04: Use rsa-sha2-512
 *
 * Returns:
 *   0 on success, negative number on failure
 *
 * The signature blob format follows the SSH agent protocol:
 *   4 bytes - Length of algorithm name
 *   n bytes - Algorithm name string
 *   4 bytes - Length of signature
 *   m bytes - Signature data
 */
LIBSSH2_API int
libssh2_sign_with_keydata(LIBSSH2_SESSION *session,
                          const char *keydata,
                          size_t keydata_len,
                          const char *passphrase,
                          int datavec,
                          const struct iovec data[],
                          unsigned char **signature,
                          size_t *signature_len,
                          unsigned int flags)
{
    const LIBSSH2_HOSTKEY_METHOD **hostkey_methods = libssh2_hostkey_methods();
    const LIBSSH2_HOSTKEY_METHOD *method = NULL;
    void *abstract = NULL;
    int rc;
    unsigned char *pubkeydata = NULL;
    size_t pubkeydata_len = 0;
    unsigned char *methodname = NULL;
    size_t methodname_len = 0;
    unsigned char *raw_sig = NULL;
    size_t raw_sig_len = 0;
    unsigned char *blob = NULL;
    unsigned char *p;
    unsigned char const *selected_method = NULL;
    size_t selected_method_len = 0;

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

     /* Non-RSA key, use the original method */
     selected_method = methodname;
     selected_method_len = methodname_len;

    /*
     * Handle RSA signing method selection based on flags
     * The default "ssh-rsa" method will be used for non-RSA keys regardless of flags
     */
    if(methodname_len == 7 && memcmp(methodname, "ssh-rsa", 7) == 0) {
        if(flags & 0x04) {
            /* Use rsa-sha2-512 */
            selected_method = (unsigned char const*)"rsa-sha2-512";
            selected_method_len = 12;

            /* Set the signing method for the session */
            if(session->userauth_pblc_method) {
                LIBSSH2_FREE(session, session->userauth_pblc_method);
                session->userauth_pblc_method = NULL;
                session->userauth_pblc_method_len = 0;
            }
            session->userauth_pblc_method = LIBSSH2_ALLOC(session, selected_method_len);
            if(session->userauth_pblc_method) {
                memcpy(session->userauth_pblc_method, selected_method, selected_method_len);
                session->userauth_pblc_method_len = selected_method_len;
            }
        }
        else if(flags & 0x02) {
            /* Use rsa-sha2-256 */
            selected_method = (unsigned char const*)"rsa-sha2-256";
            selected_method_len = 12;

            /* Set the signing method for the session */
            if(session->userauth_pblc_method) {
                LIBSSH2_FREE(session, session->userauth_pblc_method);
                session->userauth_pblc_method = NULL;
                session->userauth_pblc_method_len = 0;
            }
            session->userauth_pblc_method = LIBSSH2_ALLOC(session, selected_method_len);
            if(session->userauth_pblc_method) {
                memcpy(session->userauth_pblc_method, selected_method, selected_method_len);
                session->userauth_pblc_method_len = selected_method_len;
            }
        }
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

    /* Sign the data with the private key */
    rc = method->signv(session, &raw_sig, &raw_sig_len,
                      datavec, data, &abstract);

    if(rc) {
        if(method->dtor) {
            method->dtor(session, &abstract);
        }
        LIBSSH2_FREE(session, methodname);
        LIBSSH2_FREE(session, pubkeydata);
        return rc;
    }

    /*
     * Format the signature into an agent-compatible blob:
     * [ algorithm name length (4 bytes) ]
     * [ algorithm name string (n bytes) ]
     * [ signature length (4 bytes) ]
     * [ signature data (m bytes) ]
     *
     * Special handling for security key (SK) authentication methods
     */

    /* Check if we need to apply plain_method to get the base method name */
    size_t plain_len = 0;
    int is_sk_method = 0;

    /* Add declaration for plain_method here */
    extern size_t plain_method(char *method, size_t method_len);

    /* Apply plain_method to handle certificates properly */
    plain_len = plain_method((char *)selected_method, selected_method_len);
    if(plain_len > 0 && plain_len != selected_method_len) {
        /* Use the base method length returned by plain_method */
        selected_method_len = plain_len;
    }

    /* Check if this is a security key (SK) method that needs special handling */
    if(selected_method_len >= 3 &&
       !memcmp((const char *)selected_method, "sk-", 3)) {
        is_sk_method = 1;
    }

    /* For SK methods, we don't include the internal signature length */
    *signature_len = 4 + selected_method_len + (is_sk_method ? 0 : 4) + raw_sig_len;

    /* Allocate memory for signature blob */
    blob = LIBSSH2_ALLOC(session, *signature_len);
    if(!blob) {
        LIBSSH2_FREE(session, raw_sig);
        if(method->dtor) {
            method->dtor(session, &abstract);
        }
        LIBSSH2_FREE(session, methodname);
        LIBSSH2_FREE(session, pubkeydata);
        return _libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                             "Unable to allocate memory for signature blob");
    }

    /* Fill in the signature blob */
    p = blob;

    /* Algorithm name length */
    _libssh2_store_u32(&p, (uint32_t)selected_method_len);

    /* Algorithm name */
    memcpy(p, selected_method, selected_method_len);
    p += selected_method_len;

    if(!is_sk_method) {
        /* For regular methods, include the signature length */
        _libssh2_store_u32(&p, (uint32_t)raw_sig_len);
    }

    /* Signature data */
    memcpy(p, raw_sig, raw_sig_len);

    /* Set the output parameters */
    *signature = blob;

    /* Clean up */
    LIBSSH2_FREE(session, raw_sig);
    if(method->dtor) {
        method->dtor(session, &abstract);
    }
    LIBSSH2_FREE(session, methodname);
    LIBSSH2_FREE(session, pubkeydata);

    return 0;
}

