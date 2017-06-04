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

#include <io/IO.hpp>
#include "utils/logging.hpp"

namespace paracrypt {

const std::streampos paracrypt::IO::fileSize( std::fstream *file ){
	std::streampos save = file->tellg();

    file->seekg( 0, std::ios::end );
    const std::streampos fsize = file->tellg();

    file->seekg(save);
    return fsize;
}

const std::streampos paracrypt::IO::fileSize( std::ifstream *file ){
	return fileSize((std::fstream*)file);
}

const std::streampos paracrypt::IO::fileSize( std::string fileName ){
	std::ifstream file(fileName.c_str(),std::fstream::binary);
	if(!file) {
		FATAL(boost::format("Error reading file %s size: %s\n") % fileName % strerror(errno));
	}
	std::streampos size = fileSize(&file);
	return size;
}

} /* namespace paracrypt */
