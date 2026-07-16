/*
 * POSIX compiler definitions for the kernel-libipsec lwIP port.
 */

#ifndef KERNEL_LIBIPSEC_LWIP_ARCH_CC_H_
#define KERNEL_LIBIPSEC_LWIP_ARCH_CC_H_

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>

/* Keep the embedded stack's public names out of strongSwan's namespace. */
#define err_t lwip_err_t
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define LWIP_TIMEVAL_PRIVATE 0
#define LWIP_ERRNO_INCLUDE <errno.h>

typedef unsigned int sys_prot_t;

unsigned int kernel_libipsec_lwip_rand(void);
void kernel_libipsec_lwip_diag(const char *format, ...);
void kernel_libipsec_lwip_assert(const char *message, const char *file,
								 int line);

#define LWIP_RAND() ((uint32_t)kernel_libipsec_lwip_rand())
#define LWIP_PLATFORM_DIAG(x) kernel_libipsec_lwip_diag x
#define LWIP_PLATFORM_ASSERT(x) \
	kernel_libipsec_lwip_assert((x), __FILE__, __LINE__)

#endif /* KERNEL_LIBIPSEC_LWIP_ARCH_CC_H_ */
