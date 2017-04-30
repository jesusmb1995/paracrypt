/*
 *  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 *
 *  This file is part of Paracrypt.
 *
 *  Paracrypt is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Paracrypt is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

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

void fdump(std::string title, std::string filename)
{
	std::ifstream f(filename);
	if(f.is_open()) {
		std::stringstream stream;
		n = 0;
		while(!f.fail() || !f.eof()) {
			char buff[16];
			f.read(buff,16);
			unsigned int readed = 16;
			if(f.fail() && f.eof) {
				readed = f.gcount();
			}
			else if(f.fail()) {
				LOG_WARNING(std::format("fdump couldn't correctly read %s") % filename);
			}
			stream << boost::format("\n%s  %04x") % title % (int)n;
			for(int i = 0; i < readed; i++) {
				stream << boost::format(" %02x") % (int)buff[i];
				n++;
			}
		}
		stream << "\n";
		LOG_DEBUG(stream.str());
	} else {
		LOG_WARNING(std::format("fdump cannot open %s") % filename);
	}
}
