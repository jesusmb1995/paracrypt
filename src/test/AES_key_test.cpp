#define BOOST_TEST_MODULE My Test
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_CASE(first_test) 3
{
  int i = 1;
  BOOST_TEST(i); 4
  BOOST_TEST(i == 2); 5
}
