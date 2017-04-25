BOOST (Test)
------------

boost library download:
	http://www.boost.org

install boost unit testing library:
        boost_installation_prefix=/usr
	cd $boost_path
	./bootstrap.sh
	sudo ./b2 --with-test --with-log --with-thread --with-container --prefix=$boost_installation_prefix install
