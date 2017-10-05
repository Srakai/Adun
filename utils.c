#include "utils.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define LOG_DEGBUG 0
#define LOG_WARNING 1
#define LOG_ERROR 2

#define BUFF_MAX 1024*4

int get_longest_line(char *buff)
{
	int longest_len=0, current_len=0;
	char *c = buff;

	while(c++)
	{
		current_len++;
		if(*c=='\n')
		{
			if(current_len > longest_len)
			{
				longest_len = current_len;
				current_len=0;
			}	
		}
	}
	return longest_len;
}

// abbadoned function
int print_in_frame(char *format, ...)
{
	va_list args;
	va_start(args, format);
	
	char buff[BUFF_MAX];
	int ret;
	
	ret = vsnprintf(buff, BUFF_MAX, format, args);
	va_end(args);
	
	if(ret > BUFF_MAX)
	{
		return -1;
	}
	
	int line_len = get_longest_line(buff) + 2;
	
	// compose bufffer	
	
	char new_buff[BUFF_MAX*4];
   	char *cur_pos = new_buff;
	char border_pixel = '*';

	memset(new_buff, border_pixel, line_len);
	cur_pos += line_len;
	

}


void logs(int log_level, char *format, ...)
{
	va_list args;
	va_start(args, format);
	
	switch(log_level)
	{
		case LOG_DEGBUG:
			fprintf(stderr, "\033[92m[+] ");
			break;
		case LOG_WARNING:
			fprintf(stderr, "\033[93m[*] ");
			break;
		case LOG_ERROR:
			fprintf(stderr, "\033[91m[!] ");
			break;
	}

	vfprintf(stderr, format, args);
	fprintf(stderr, "\033[0m\n");

	va_end(args);
}


void print_binary(unsigned int v) {
    unsigned int mask = ~(~(unsigned int) 0 >> 1U);
    while (mask) {
        putchar('0'+!!(v&mask));
        mask >>= 1U;
    }
    putchar('\n');
}


void hex_dump(unsigned char *addres, unsigned int len)
{
	printf("[0]\t");
	for(int i=0;i<len;i++)
	{
		printf("%02x  ",addres[i]);
		if((i+1)%8==0)
		{
			if((i+1)%16==0)printf("\n[+%d]\t",i+1);
			else printf("    ");
		}		
	}
	printf("\n");
}
