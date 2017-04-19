#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/format.hpp>

#ifdef DEBUG
#define LOG_TRACE(str) BOOST_LOG_TRIVIAL(trace) << (str)
#define LOG_DEBUG(str) BOOST_LOG_TRIVIAL(debug) << (str)
#else
#define LOG_TRACE(str)
#define LOG_DEBUG(str)
#endif
#define LOG_INF(str) BOOST_LOG_TRIVIAL(info) << (str)
#define LOG_WAR(str) BOOST_LOG_TRIVIAL(warning) << (str)
#define LOG_ERR(str) BOOST_LOG_TRIVIAL(error) << (str)
#define LOG_FATAL(str) BOOST_LOG_TRIVIAL(fatal) << (str)

void hexdump(std::string title, const unsigned char *s, int length);
