#ifndef UTILS_H_
#define UTILS_H_

#include "utils.c"
void hex_dump(unsigned char *addres, unsigned int len);

void print_binary(unsigned int v);

void logs(int log_lvl, char *format, ...);

#endif
