/* IPFIX utility functions
 *
 * (C) 2014 by Eric Leblond <eric@regit.org>
 * (C) 2014 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 * This code is distributed under the terms of GNU GPL version 2
 */

#ifndef _IPFIX_UTILS_H_
#define _IPFIX_UTILS_H_

#include <byteswap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	(x)
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	(x)
#  endif
# else
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	__bswap_64(x)
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	__bswap_64(x)
#  endif
# endif
#endif

int open_connect_descriptor(const char *dest);
int ulogd_key_putn(struct ulogd_key *key, void *buf, int buflen);
uint8_t event_ct_to_firewall(uint32_t ct_event);
#endif
