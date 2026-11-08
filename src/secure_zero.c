#include "secure_zero.h"

void secure_zero(void* data, size_t size) {
    volatile unsigned char* bytes = (volatile unsigned char*)data;
    while (size-- != 0) {
        *bytes++ = 0;
    }
}
