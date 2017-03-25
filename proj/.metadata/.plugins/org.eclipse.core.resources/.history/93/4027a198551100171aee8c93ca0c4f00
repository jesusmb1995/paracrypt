#include "logging.hpp"

void hexdump(FILE * f, const char *title, const unsigned char *s, int length)
{
    for (int n = 0; n < length; ++n) {
	if ((n % 16) == 0)
	    fprintf(f, "\n%s  %04x", title, n);
	fprintf(f, " %02x", s[n]);
    }
    fprintf(f, "\n");
}
