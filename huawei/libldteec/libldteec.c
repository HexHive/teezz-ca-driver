#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <logging.h>
#include <libldteec.h>

static int libtcteec_get_lib_sym(libtcteec_handle_t *handle)
{
    handle->libhandle = dlopen("libteec.so", RTLD_NOW | RTLD_GLOBAL);
    if (handle->libhandle)
    {
        *(void **)(&handle->ops.TEEC_InitializeContext) =
            dlsym(handle->libhandle, "TEEC_InitializeContext");
        if (handle->ops.TEEC_InitializeContext == NULL)
        {
            LOGE("dlsym: Error loading TEEC_InitializeContext");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FinalizeContext) =
            dlsym(handle->libhandle, "TEEC_FinalizeContext");
        if (handle->ops.TEEC_FinalizeContext == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FinalizeContext");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_OpenSession) =
            dlsym(handle->libhandle, "TEEC_OpenSession");
        if (handle->ops.TEEC_OpenSession == NULL)
        {
            LOGE("dlsym: Error loading TEEC_OpenSession");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_CloseSession) =
            dlsym(handle->libhandle, "TEEC_CloseSession");
        if (handle->ops.TEEC_CloseSession == NULL)
        {
            LOGE("dlsym: Error loading TEEC_CloseSession");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_InvokeCommand) =
            dlsym(handle->libhandle, "TEEC_InvokeCommand");
        if (handle->ops.TEEC_InvokeCommand == NULL)
        {
            LOGE("dlsym: Error loading TEEC_InvokeCommand");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_RegisterSharedMemory) =
            dlsym(handle->libhandle, "TEEC_RegisterSharedMemory");
        if (handle->ops.TEEC_RegisterSharedMemory == NULL)
        {
            LOGE("dlsym: Error loading TEEC_RegisterSharedMemory");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_AllocateSharedMemory) =
            dlsym(handle->libhandle, "TEEC_AllocateSharedMemory");
        if (handle->ops.TEEC_AllocateSharedMemory == NULL)
        {
            LOGE("dlsym: Error loading TEEC_AllocateSharedMemory");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_ReleaseSharedMemory) =
            dlsym(handle->libhandle, "TEEC_ReleaseSharedMemory");
        if (handle->ops.TEEC_ReleaseSharedMemory == NULL)
        {
            LOGE("dlsym: Error loading TEEC_ReleaseSharedMemory");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_RequestCancellation) =
            dlsym(handle->libhandle, "TEEC_RequestCancellation");
        if (handle->ops.TEEC_RequestCancellation == NULL)
        {
            LOGE("dlsym: Error loading TEEC_RequestCancellation");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_InitStorageService) =
            dlsym(handle->libhandle, "TEEC_InitStorageService");
        if (handle->ops.TEEC_InitStorageService == NULL)
        {
            LOGE("dlsym: Error loading TEEC_InitStorageService");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_UninitStorageService) =
            dlsym(handle->libhandle, "TEEC_UninitStorageService");
        if (handle->ops.TEEC_UninitStorageService == NULL)
        {
            LOGE("dlsym: Error loading TEEC_UninitStorageService");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_GetFErr) =
            dlsym(handle->libhandle, "TEEC_GetFErr");
        if (handle->ops.TEEC_GetFErr == NULL)
        {
            LOGE("dlsym: Error loading TEEC_GetFErr");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FOpen) =
            dlsym(handle->libhandle, "TEEC_FOpen");
        if (handle->ops.TEEC_FOpen == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FOpen");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FRead) =
            dlsym(handle->libhandle, "TEEC_FRead");
        if (handle->ops.TEEC_FRead == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FRead");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FWrite) =
            dlsym(handle->libhandle, "TEEC_FWrite");
        if (handle->ops.TEEC_FWrite == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FWrite");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FSeek) =
            dlsym(handle->libhandle, "TEEC_FSeek");
        if (handle->ops.TEEC_FSeek == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FSeek");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FClose) =
            dlsym(handle->libhandle, "TEEC_FClose");
        if (handle->ops.TEEC_FClose == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FClose");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FSync) =
            dlsym(handle->libhandle, "TEEC_FSync");
        if (handle->ops.TEEC_FSync == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FSync");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
        *(void **)(&handle->ops.TEEC_FCloseAndDelete) =
            dlsym(handle->libhandle, "TEEC_FCloseAndDelete");
        if (handle->ops.TEEC_FCloseAndDelete == NULL)
        {
            LOGE("dlsym: Error loading TEEC_FCloseAndDelete");
            dlclose(handle->libhandle);
            handle->libhandle = NULL;
            return -1;
        }
    }
    else
    {
        LOGE("failed to load teec library");
        LOGE("%s", dlerror());
        return -1;
    }

    void *tcpreload_handle = dlopen("./tcpreload", RTLD_NOW | RTLD_GLOBAL);
    if (tcpreload_handle)
    {
        *(void **)(&handle->ops.TEEC_InitializeContext) =
            dlsym(tcpreload_handle, "TEEC_InitializeContext");
        if (handle->ops.TEEC_InitializeContext == NULL)
        {
            LOGE("dlsym: Error loading TEEC_InitializeContext");
            dlclose(tcpreload_handle);
            return -1;
        }
    }
    else
    {
        LOGE("failed to load tcpreload library");
        LOGE("%s", dlerror());
        return -1;
    }
    return 0;
}

libtcteec_handle_t *init_libtcteec_handle()
{
    libtcteec_handle_t *handle =
        (libtcteec_handle_t *)calloc(1, sizeof(libtcteec_handle_t));
    if (handle == NULL)
    {
        LOGE("Memalloc for libteec handle failed!");
        return NULL;
    }
    handle->libhandle = NULL;
    int ret = libtcteec_get_lib_sym(handle);
    if (ret < 0)
    {
        LOGE("get_lib_syms failed!");
        free(handle);
        return NULL;
    }
    LOGI("Successfully loaded libteec");
    return handle;
}
