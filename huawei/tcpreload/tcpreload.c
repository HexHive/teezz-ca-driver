#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/prctl.h>

#include <tc_ns_client.h>
#include <tee_client_constants.h>

#include <logging.h>

#define TC_NS_CLIENT_DEV_NAME "/dev/tc_ns_client"
#define LOGIN_BLOB_ENV_VAR "LOGIN_BLOB"

typedef struct tc_context
{
    int fd;
    int regMem;
    char *appPath;
    uint64_t reserved[4];
} TC_Context;

int (*o_TEEC_InitializeContext)(const char *name, TC_Context *context);

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *)-1l)
#endif

// thx https://stackoverflow.com/questions/50627097/hexlify-and-unhexlify-functions-in-c

int a2v(char c)
{
    if ((c >= '0') && (c <= '9'))
    {
        return c - '0';
    }
    if ((c >= 'a') && (c <= 'f'))
    {
        return c - 'a' + 10;
    }
    else
        return 0;
}

char v2a(int c)
{
    const char hex[] = "0123456789abcdef";
    return hex[c];
}

char *unhexlify(char *hstr)
{
    char *bstr = malloc((strlen(hstr) / 2) + 1);
    char *pbstr = bstr;
    for (int i = 0; i < strlen(hstr); i += 2)
    {
        char c = (a2v(hstr[i]) << 4) + a2v(hstr[i + 1]);
        if (c == 0)
        {
            *pbstr++ = '\0';
        }
        else
        {
            *pbstr++ = c;
        }
    }
    *pbstr++ = '\0';
    return bstr;
}

char *hexlify(char *bstr)
{
    char *hstr = malloc((strlen(bstr) * 2) + 1);
    char *phstr = hstr;
    for (int i = 0; i < strlen(bstr); i++)
    {
        if (bstr[i] == -128)
        {
            *phstr++ = '0';
            *phstr++ = '0';
        }
        else
        {
            *phstr++ = v2a((bstr[i] >> 4) & 0x0F);
            *phstr++ = v2a((bstr[i]) & 0x0F);
        }
    }
    *phstr++ = '\0';
    return hstr;
}

int need_load_app(TC_Context *ctx)
{

    TC_NS_ClientContext tc_ctx;
    tc_ctx.started = 0;
    tc_ctx.cmd_id = 1;
    uint64_t sz = 16;
    uint8_t *mem = NULL;

    LOGI("mmap");
    mem = mmap(0, sz, 3, 1, ctx->fd, 0);
    if (mem == (uint8_t *)-1)
    {
        LOGE("mmap failed");
    }
    memcpy(mem, "\x81\x15\xb7\xb4\xd2\xad\x9f\xe8\xd5\x36\xf3\x54\x36\xdc\x79\x73", 16); // antitheft

    tc_ctx.params[0].memref.buffer = (__u64)mem;
    tc_ctx.params[0].memref.size_addr = (__u64)&sz;
    tc_ctx.paramTypes = TEEC_MEMREF_PARTIAL_INOUT;

    LOGI("ioctl");
    int ret = ioctl(ctx->fd, TC_NS_CLIENT_IOCTL_NEED_LOAD_APP, &tc_ctx);

    if (ret != 0)
    {
        LOGE("TC_NS_CLIENT_IOCTL_NEED_LOAD_APP ret %#x", ret);
    }
    else
    {

        LOGI("TC_NS_CLIENT_IOCTL_NEED_LOAD_APP ret %#x", ret);
    }

    LOGI("munmap");
    ret = munmap(mem, sz);
    if (ret != 0)
    {
        LOGE("munmap failed ret %#x", ret);
    }

    return 0;
}

int TEEC_InitializeContext(const char *name, TC_Context *ctx)
{
    int ret = 0;

    LOGD("%s", __FUNCTION__);
    // o_ioctl = dlsym(RTLD_NEXT, "TEEC_InitializeContext");

    int fd = open(TC_NS_CLIENT_DEV_NAME, O_RDWR);
    if (fd == -1)
    {
        perror("open");
        LOGE("Failed to get an fd to %s", TC_NS_CLIENT_DEV_NAME);
        ret = -1;
        goto err;
    }

    // set gid/uid for interaction with ioctl device
    int uid = 1000;
    if (0 != setgid(uid))
    {
        perror("setgid");
        goto err_clean;
    }

    if (0 != setuid(uid))
    {
        perror("setuid");
        goto err_clean;
    }

    // prctl(PR_GET_NAME, "com.huawei.systemmanager", 0, 0, 0);

    // package_name_len(4 bytes) || package_name || exe_uid_len(4 bytes) || exe_uid
    char *login_blob_hex = getenv(LOGIN_BLOB_ENV_VAR);
    if (!login_blob_hex)
    {
        LOGE("%s not found.", LOGIN_BLOB_ENV_VAR);
        return -1;
    }

    char *login_blob = unhexlify(login_blob_hex);

    ret = ioctl(fd, TC_NS_CLIENT_IOCTL_LOGIN, login_blob);
    if (0 > ret)
    {
        LOGE("TC_NS_CLIENT_IOCTL_LOGIN ret %#x", ret);
    }
    else
    {
        LOGD("TC_NS_CLIENT_IOCTL_LOGIN ret %#x", ret);
    }
    ctx->fd = fd;
    ctx->reserved[0] = (uint64_t)&ctx->reserved;
    ctx->reserved[1] = (uint64_t)&ctx->reserved;

    ctx->reserved[2] = (uint64_t)&ctx->reserved[2];
    ctx->reserved[3] = (uint64_t)&ctx->reserved[2];

    // need_load_app(ctx);

    LOGD("Returning from TEEC_InitializeContext");
err:
    return ret;
err_clean:
    close(fd);
    return ret;
}
