#include "logging.hpp"

void hexdump(std::string title, const unsigned char *s, int length)
{
	std::stringstream stream;
    for (int n = 0; n < length; ++n) {
	if ((n % 16) == 0)
		stream << boost::format("\n%s  %04x") % title % (int)n;
	stream << boost::format(" %02x") % (int)s[n];
    }
    stream << "\n";
    LOG_DEBUG(stream.str());
}
