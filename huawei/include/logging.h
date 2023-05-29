#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdio.h>

#define LOGD(fmt, args...) printf("[+] " fmt "\n", ##args)
#define LOGI(fmt, args...) printf("[*] " fmt "\n", ##args)
#define LOGE(fmt, args...) fprintf(stdout, "[-] " fmt "\n", ##args)

#endif // _LOGGING_H_
