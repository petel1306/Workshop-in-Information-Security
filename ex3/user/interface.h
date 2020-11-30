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
#define INFO(message, ...) printf("\nFirewall_user-%d: " message "\n\n", get_info_counter(), ##__VA_ARGS__);

/*
 * Print debug messages to the user (in case DEBUG is defined)
 */
// #define DEBUG

#ifdef DEBUG
#define DINFO(message, ...) printf("\nFirewall_user-%d debug: " message "\n\n", get_info_counter(), ##__VA_ARGS__);
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

#define VAR2BUF(var) var2buf(&buf, &var, sizeof(var))
#define BUF2VAR(var) buf2var(&buf, &var, sizeof(var))

#define STR2BUF(str, n) var2buf(&buf, str, n)
#define BUF2STR(str, n) buf2var(&buf, str, n)

// Conversion of objects to/ from strings
char *action2str(const uint8_t action);
uint8_t str2action(const char *str, uint8_t *action);

char *protocol2str(const uint8_t protocol);
uint8_t str2protocol(const char *str, uint8_t *protocol);

void ip2str(char *ip_str, const uint32_t ip);
uint8_t str2ip(const char *str, uint32_t *ip);

void port2str(char *str_port, const uint16_t port);
uint8_t str2port(const char *str_port, uint16_t *port);

#endif