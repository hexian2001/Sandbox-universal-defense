#include<stdio.h>
#include<stdlib.h>
void main()
{
	char (*v4)(void);
	char *buf="\x55\x48\x89\xE5\x49\xC7\xC7\x06\x00\x00\x00\x41\x57\x49\xBF\x06\x00\x00\x00\x00\x00\xFF\x7F\x41\x57\x49\xBF\x15\x00\x01\x00\x3B\x00\x00\x00\x41\x57\x49\xBF\x15\x00\x02\x00\x38\x00\x00\x00\x41\x57\x49\xBF\x15\x00\x03\x00\x32\x00\x00\x00\x41\x57\x49\xBF\x15\x00\x04\x00\x31\x00\x00\x00\x41\x57\x49\xBF\x15\x00\x05\x00\x2A\x00\x00\x00\x41\x57\x49\xBF\x15\x00\x06\x00\x29\x00\x00\x00\x41\x57\x49\xBF\x35\x00\x07\x00\x00\x00\x00\x40\x41\x57\x49\xC7\xC7\x20\x00\x00\x00\x41\x57\x49\xBF\x15\x00\x00\x09\x3E\x00\x00\xC0\x41\x57\x49\xBF\x20\x00\x00\x00\x04\x00\x00\x00\x41\x57\x49\x89\xE7\x41\x57\x49\xC7\xC7\x0C\x00\x00\x00\x41\x57\x49\x89\xE7\x41\x57\x48\xC7\xC7\x26\x00\x00\x00\x48\xC7\xC6\x01\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x48\xC7\xC1\x00\x00\x00\x00\x49\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC0\x9D\x00\x00\x00\x0F\x05\x48\xC7\xC7\x16\x00\x00\x00\x48\xC7\xC6\x02\x00\x00\x00\x4C\x89\xFA\x48\xC7\xC0\x9D\x00\x00\x00\x0F\x05\xC9\xC3\x0A";
	v4=buf;
	
	v4();
	//system("/bin/sh");

	return 0;
}