#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int get_info_counter(void);

/*
 * Print messgas to the user
 */
#define INFO(message, ...) printf("\nFirewall_user-%d debug: " message "\n", get_info_counter(), ##__VA_ARGS__);

/*
 * Print debug messages to the user (in case DEBUG is defined)
 */
#define DEBUG
#ifdef DEBUG
#define DINFO(message, ...) printf("\nFirewall_user-%d debug: " message "\n", get_info_counter(), ##__VA_ARGS__);
#else
#define DINFO(...)
#endif

/**
 * Copy var to buffer, and increment the pointer of the bufer
 */
void var2buf(char **buf_ptr, const void *var, size_t n);

/**
 * Copy buffer to var, and increment the pointer of the bufer
 */
void buf2var(const char **buf_ptr, void *var, size_t n);

#define VAR2BUF(var) var2buf(&buf, var, sizeof(var))
#define BUF2VAR(var) buf2var(&buf, var, sizeof(var))

// the protocols we will work with
typedef enum
{
    PROT_ICMP = 1,
    PROT_TCP = 6,
    PROT_UDP = 17,
    PROT_ANY = 143,
} prot_t;

#endif