/*
**  Copyright (c) 2016, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _BASE64_H_
#define _BASE64_H_

/* system includes */
#include <sys/types.h>

/* prototypes */
extern int arc_base64_decode(u_char *str, u_char *buf, size_t buflen);
extern int arc_base64_encode(u_char *data, size_t datalen, u_char *buf,
                             size_t buflen);

#endif /* ! _BASE64_H_ */
