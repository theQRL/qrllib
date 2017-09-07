/*
This code was taken from the XMSS reference implementation by Andreas Hülsing and Joost Rijneveld and is public domain.
*/

#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <stdlib.h>
#include <stdint.h>

void to_byte(unsigned char *output, unsigned long long in, uint32_t bytes);
void hexdump(const unsigned char *a, size_t len);
#endif