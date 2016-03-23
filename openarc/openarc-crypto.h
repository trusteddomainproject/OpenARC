/*
**  Copyright (c) 2016, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _ARC_CRYPTO_H_
#define _ARC_CRYPTO_H_

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* PROTOTYPES */
extern int arcf_crypto_init __P((void));
extern void arcf_crypto_free __P((void));

#endif /* _ARC_CRYPTO_H_ */
