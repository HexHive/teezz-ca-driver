#include <libldteec.h>
#include <logging.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tc_ns_client.h>
#include <tee_client_api.h>
#include <tee_client_constants.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void hexdump(char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n", len);
        return;
    }
    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }
        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}

/**
 * Test: Open - Write - Seek - Read - CloseDelete
 * @param inbuf      A buffer with the data to be written.
 * @param outbuf     A buffer with the data to be written.
 * @param size       The size of @buf.
 * @return nwritten  The number of bytes written.
 */
uint32_t test_write_read_delete(libtcteec_handle_t *libteec, char *inbuf, char *outbuf, uint32_t size) {
    enum TEEC_Result res;

    LOGD("%s", __FUNCTION__);

    // Open file test with O_RDWR | O_DELETABLE | O_CREAT | O_TRUNC
    // this is on p9lite
    char *path = "/sec_storage/teezz_testing";  // "/sec_storage/test"
    // int fd = libteec->ops.TEEC_FOpen(path, 03 | 04 | 01000);
    int fd = libteec->ops.TEEC_FOpen(path, 03 | 04 | 01000);
secur
    if (fd == -1) {
        LOGE("TEEC_FOpen: %#x\nDoes the path exist?", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    LOGD("Got fd %d", fd);

    // Read data into the file
    uint32_t nwritten = libteec->ops.TEEC_FWrite(fd, inbuf, size);
    if (nwritten == 0) {
        fprintf(stderr, "TEEC_FWrite2: %#x", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    // Seek to the beginning of the file
    if (libteec->ops.TEEC_FSeek(fd, 0, SEEK_SET) != 0) {
        fprintf(stderr, "TEEC_FSeek: %#x", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    // Read data from file into (ta) addr
    uint32_t nread = libteec->ops.TEEC_FRead(fd, outbuf, size);
    if (nread == 0) {
        fprintf(stderr, "TEEC_FRead: %#x", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    // Delete the file
    libteec->ops.TEEC_FCloseAndDelete(fd);
    return nread;
}

/**
 * Test: Open - Write - Seek - Read - Sync - Close
 * @param inbuf      A buffer with the data to be written.
 * @param outbuf     A buffer with the data to be written.
 * @param size       The size of @buf.
 * @return nwritten  The number of bytes written.
 */
uint32_t test_write_read_sync(libtcteec_handle_t *libteec, char *inbuf, char *outbuf, uint32_t size) {
    enum TEEC_Result res;

    LOGD("%s", __FUNCTION__);

    // Open file test with O_RDWR | O_DELETABLE | O_CREAT | O_TRUNC
    // this is on p9lite
    char *path = "/sec_storage/teezz_testing";  // "/sec_storage/test"
    // int fd = libteec->ops.TEEC_FOpen(path, 03 | 04 | 01000);
    int fd = libteec->ops.TEEC_FOpen(path, 03 | 04 | 01000);

    if (fd == -1) {
        LOGE("TEEC_FOpen: %#x\nDoes the path exist?", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    LOGD("Got fd %d", fd);
    // Read data into the file
    uint32_t nwritten = libteec->ops.TEEC_FWrite(fd, inbuf, size);
    if (nwritten == 0) {
        fprintf(stderr, "TEEC_FWrite2: %#x", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    // Seek to the beginning of the file
    if (libteec->ops.TEEC_FSeek(fd, 0, SEEK_SET) != 0) {
        fprintf(stderr, "TEEC_FSeek: %#x", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    // Read data from file into (ta) addr
    uint32_t nread = libteec->ops.TEEC_FRead(fd, outbuf, size);
    if (nread == 0) {
        fprintf(stderr, "TEEC_FRead: %#x", libteec->ops.TEEC_GetFErr());
        return 0;
    }

    libteec->ops.TEEC_FSync(fd);
    libteec->ops.TEEC_FClose(fd);
    return nread;
}

int open_session(libtcteec_handle_t *libteec, TEEC_Context *ctx, TEEC_Session *sess) {
    enum TEEC_Result res = 0;
    TEEC_UUID uuid = {0};
    TEEC_Operation op = {0};
    uint32_t origin = 0;

    memcpy(&uuid, "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02", 16);

    op.cmd = 0x1;
    op.paramTypes = 0x5500;

    LOGD("OpenSession");
    res = libteec->ops.TEEC_OpenSession(ctx, sess, &uuid, 7, (void *)0x0, &op, &origin);
    LOGD("origin: %#x", origin);
    hexdump("Session:", sess, 64);
    LOGD("OpenSession returns: %#x", res);

    free(op.params[2].tmpref.buffer);
    free(op.params[3].tmpref.buffer);
    return 0;
}

int main(int argc, char *argv[]) {
    // Ensure argv[0] == "com.huawei.hidisk"
    /*
    if (strcmp(argv[0], "com.huawei.hidisk") != 0) {
            execl(argv[0], "com.huawei.hidisk", NULL);
            die("execl");
    }
    */

    enum TEEC_Result res;
    libtcteec_handle_t *libteec = init_libtcteec_handle();

    // for secure storage, we do not need to init the `ctx` and open the `session`
    // ourselves, the tee library is taking care of this for us inside of
    // `TEEC_InitStorageService`. The `ctx` and the `session` are kept as
    // internal state in the library.
    // TEEC_Context ctx = { 0 };
    // TEEC_Session sess = { 0 };
    // int ret = init(libteec, &ctx, &sess);

    LOGD("Entering TEEC_InitStorageService");

    // Initialize Storage Service
    if ((res = libteec->ops.TEEC_InitStorageService()) != TEEC_SUCCESS) {
        fprintf(stderr, "TEEC_InitStorageService: 0x%x", res);
        return 0;
    }

    /*
     *   Open - Write - Seek - Read - CloseDelete
     */
    char *inbuf = calloc(1, 0x100);
    memset(inbuf, '\x41', 0x100 - 1);
    LOGD("inbuf: %s\n", inbuf);
    char *outbuf = calloc(1, 0x100);
    test_write_read_delete(libteec, inbuf, outbuf, 0x100);
    outbuf[0x100 - 1] = '\x00';
    LOGD("outbuf: %s\n", outbuf);

    memset(inbuf, '\x42', 0x100 - 1);
    LOGD("inbuf: %s\n", inbuf);
    test_write_read_sync(libteec, inbuf, outbuf, 0x100);
    LOGD("outbuf: %s\n", outbuf);

    // Cleanup
    libteec->ops.TEEC_UninitStorageService();
    return 0;
}
