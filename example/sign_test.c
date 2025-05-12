/*
 * Sample showing how to use the libssh2_sign_with_keydata() function to sign data.
 *
 * The sample code has been based on other libssh2 example code.
 * Feel free to use this as you wish.
 */

#include "libssh2_config.h"
#include <libssh2.h>

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char *keyfile = "~/.ssh/id_rsa";
static const char *passphrase = "";
static unsigned int sign_flags = 0; /* 0=ssh-rsa, 2=rsa-sha2-256, 4=rsa-sha2-512 */

int main(int argc, char *argv[])
{
    /* Usage message */
    if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        fprintf(stderr, "Usage: %s [keyfile] [passphrase] [flags]\n", argv[0]);
        fprintf(stderr, "  keyfile: Path to private key file (default: ~/.ssh/id_rsa)\n");
        fprintf(stderr, "  passphrase: Optional passphrase for encrypted key\n");
        fprintf(stderr, "  flags: RSA signing method\n");
        fprintf(stderr, "         0 = ssh-rsa (default)\n");
        fprintf(stderr, "         2 = rsa-sha2-256\n");
        fprintf(stderr, "         4 = rsa-sha2-512\n");
        return 1;
    }
    LIBSSH2_SESSION *session = NULL;
    int rc;
    struct iovec datavec[1];
    char *testdata = "This is test data to sign";
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    FILE *fp;
    char *keydata = NULL;
    long keylen;

    /* Parse command-line arguments */
    if(argc > 1) {
        keyfile = argv[1];
    }
    if(argc > 2) {
        passphrase = argv[2];
    }
    if(argc > 3) {
        /* Parse flags: 0=ssh-rsa, 2=rsa-sha2-256, 4=rsa-sha2-512 */
        sign_flags = (unsigned int)atoi(argv[3]);
    }

    /* Read the key from the file */
    fp = fopen(keyfile, "rb");
    if(fp == NULL) {
        fprintf(stderr, "Failed to open private key file %s\n", keyfile);
        return 1;
    }

    /* Determine file size */
    fseek(fp, 0, SEEK_END);
    keylen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Allocate memory and read the key */
    keydata = malloc(keylen);
    if(keydata == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(fp);
        return 1;
    }

    if(fread(keydata, 1, keylen, fp) != (size_t)keylen) {
        fprintf(stderr, "Failed to read private key file\n");
        free(keydata);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    /* Initialize libssh2 */
    rc = libssh2_init(0);
    if(rc != 0) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        free(keydata);
        return 1;
    }

    /* Create a session instance */
    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "Failed to create session\n");
        libssh2_exit();
        free(keydata);
        return 1;
    }

    /* Initialize data to sign */
    datavec[0].iov_base = testdata;
    datavec[0].iov_len = strlen(testdata);

    /* Sign the data */
    rc = libssh2_sign_with_keydata(session, keydata, keylen, passphrase,
                                  1, datavec, &signature, &signature_len,
                                  sign_flags);

    /* Display the result */
    if(rc != 0) {
        fprintf(stderr, "Sign operation failed (%d)\n", rc);
    }
    else {
        fprintf(stdout, "Signature blob generated successfully! Total length: %zu bytes\n",
               signature_len);

        /* Display the flags used for signing */
        fprintf(stdout, "Signing flags used: 0x%02x ", sign_flags);
        if(sign_flags == 0x04) {
            fprintf(stdout, "(rsa-sha2-512)\n");
        }
        else if(sign_flags == 0x02) {
            fprintf(stdout, "(rsa-sha2-256)\n");
        }
        else {
            fprintf(stdout, "(ssh-rsa)\n");
        }

        /* Extract the algorithm name length (first 4 bytes) */
        unsigned int algo_len = (unsigned int)signature[0] << 24 |
                                (unsigned int)signature[1] << 16 |
                                (unsigned int)signature[2] << 8 |
                                (unsigned int)signature[3];

        /* Display the algorithm name */
        fprintf(stdout, "Algorithm name length: %u bytes\n", algo_len);
        fprintf(stdout, "Algorithm name: ");
        for(unsigned int i = 0; i < algo_len; i++) {
            fprintf(stdout, "%c", signature[4 + i]);
        }
        fprintf(stdout, "\n");

        /* Extract the signature length */
        unsigned int sig_len = (unsigned int)signature[4 + algo_len] << 24 |
                               (unsigned int)signature[4 + algo_len + 1] << 16 |
                               (unsigned int)signature[4 + algo_len + 2] << 8 |
                               (unsigned int)signature[4 + algo_len + 3];

        fprintf(stdout, "Signature data length: %u bytes\n", sig_len);

        /* Print part of the actual signature (first 16 bytes in hex) */
        fprintf(stdout, "Signature data preview: ");
        unsigned int offset = 4 + algo_len + 4;
        unsigned int preview_len = sig_len > 16 ? 16 : sig_len;
        for(unsigned int i = 0; i < preview_len; i++) {
            fprintf(stdout, "%02x", signature[offset + i]);
        }
        fprintf(stdout, "...\n");

        /* Free the signature - it was allocated by libssh2 */
        libssh2_free(session, signature);
    }

    /* Clean up */
    libssh2_session_free(session);
    libssh2_exit();
    free(keydata);

    return (rc == 0) ? 0 : 1;
}