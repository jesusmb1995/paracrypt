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
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
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
