#define __LOG_MSG__(level,fmt,...) \
		printf( \
				"[%s:%d:%s()] [%s]\t" fmt "\n", \
                __FILE__, \
                __LINE__, \
                __func__, \
                level, \
                __VA_ARGS__ \
		)

#ifdef DEBUG
#define __LOG_TRACE__(fmt,...) __LOG_MSG__("trace",fmt,__VA_ARGS__)
#define __LOG_DEBUG__(fmt,...) __LOG_MSG__("debug",fmt,__VA_ARGS__)
#else
#define __LOG_TRACE__(fmt,...)
#define __LOG_DEBUG__(fmt,...)
#endif
#define __LOG_INF__(fmt,...) __LOG_MSG__("info",fmt,__VA_ARGS__)
#define __LOG_WAR__(fmt,...) __LOG_MSG__("warning",fmt,__VA_ARGS__)
#define __LOG_ERR__(fmt,...) __LOG_MSG__("error",fmt,__VA_ARGS__)
#define __LOG_FATAL__(fmt,...) __LOG_MSG__("fatal",fmt,__VA_ARGS__)