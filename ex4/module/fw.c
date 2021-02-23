#include "fw.h"



static unsigned int info_counter = 0;

unsigned int get_info_counter(void)
{
    return ++info_counter;
}

/**
 * Copy var to buffer, and increment the pointer of the bufer
 */
void var2buf(char **buf_ptr, const void *var, size_t n)
{
    memcpy(*buf_ptr, var, n);
    *buf_ptr += n;
}

/**
 * Copy buffer to var, and increment the pointer of the bufer
 */
void buf2var(const char **buf_ptr, void *var, size_t n)
{
    memcpy(var, *buf_ptr, n);
    *buf_ptr += n;
}