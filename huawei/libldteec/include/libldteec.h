#ifndef _OPTEE_H_
#define _OPTEE_H_

#include <tee_client_api.h>

typedef struct libtcteec_ops {
    enum TEEC_Result (*TEEC_InitializeContext)(const char *name, TEEC_Context *ctx);
    void (*TEEC_FinalizeContext)(TEEC_Context *ctx);
    enum TEEC_Result (*TEEC_OpenSession)(TEEC_Context *ctx, TEEC_Session *session,
                                    const TEEC_UUID *destination,
                                    uint32_t connection_method,
                                    const void *connection_data,
                                    TEEC_Operation *operation,
                                    uint32_t *returnOrigin);
    void (*TEEC_CloseSession)(TEEC_Session *session);
    enum TEEC_Result (*TEEC_InvokeCommand)(TEEC_Session *session, uint32_t commandID,
                                      TEEC_Operation *operation,
                                      uint32_t *returnOrigin);
    enum TEEC_Result (*TEEC_RegisterSharedMemory)(TEEC_Context *context,
                                             TEEC_SharedMemory *sharedMem);
    enum TEEC_Result (*TEEC_AllocateSharedMemory)(TEEC_Context *context,
                                             TEEC_SharedMemory *sharedMem);
    void (*TEEC_ReleaseSharedMemory)(TEEC_SharedMemory *sharedMemory);
    void (*TEEC_RequestCancellation)(TEEC_Operation *operation);
    enum TEEC_Result (*TEEC_InitStorageService)(void);
    enum TEEC_Result (*TEEC_UninitStorageService)(void);
    enum TEEC_Result (*TEEC_GetFErr)(void);
    int (*TEEC_FOpen)(const char *pathname, int flags);
    uint32_t (*TEEC_FRead)(int fd, char *buf, uint32_t size);
    uint32_t (*TEEC_FWrite)(int fd, const char *buf, uint32_t size);
    int (*TEEC_FSeek)(int fd, long offset, int whence);
    int (*TEEC_FClose)(int fd);
    int (*TEEC_FSync)(int fd);
    int (*TEEC_FCloseAndDelete)(int fd);
} libtcteec_ops_t;

typedef struct libtcteec_handle {
    void *libhandle;
    libtcteec_ops_t ops;
} libtcteec_handle_t;

libtcteec_handle_t *init_libtcteec_handle();

#endif // _OPTEE_H_
