#include "logging.hpp"

void init()
{
	boost::log::core::get()->set_filter
    (
    		boost::log::trivial::severity >= boost::log::trivial::trace
    );
}

int main()
{
	init();
	//std::string str = "test";
	//std::string format = boost::format("\n%s") % str;
	//LOG_DEBUG("a");
	BOOST_LOG_TRIVIAL(debug) << "a";
}
