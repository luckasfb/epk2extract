/*
 * epk.h
 *
 *  Created on: 16.02.2011
 *      Author: sirius
 */

#ifndef EPK_H_
#define EPK_H_

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <config.h>

enum epakType { EPAK_OLD, EPAK_OLD_BE, EPAK_NEW, EPAK2 };
extern int type;


#endif /* EPK_H_ */
