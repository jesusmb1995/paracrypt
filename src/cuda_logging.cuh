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

#define __LOG_MSG__(level,fmt,...) \
		printf( \
				"[%s:%d:%s()] [%s]\t" fmt "\n", \
                __FILE__, \
                __LINE__, \
                __func__, \
                level, \
                __VA_ARGS__ \
		)

#if defined(DEBUG) && defined(DEVEL)
#define __LOG_TRACE__(fmt,...) __LOG_MSG__("trace",fmt,__VA_ARGS__)
#define __LOG_DEBUG__(fmt,...) __LOG_MSG__("debug",fmt,__VA_ARGS__)
#else
#define __LOG_TRACE__(fmt,...)
#define __LOG_DEBUG__(fmt,...)
#endif
#ifdef DEVEL
#define __LOG_INF__(fmt,...) __LOG_MSG__("info",fmt,__VA_ARGS__)
#define __LOG_WAR__(fmt,...) __LOG_MSG__("warning",fmt,__VA_ARGS__)
#define __LOG_ERR__(fmt,...) __LOG_MSG__("error",fmt,__VA_ARGS__)
#define __LOG_FATAL__(fmt,...) __LOG_MSG__("fatal",fmt,__VA_ARGS__)
#endif
