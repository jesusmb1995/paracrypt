BOOST (Test)
------------

boost library download:
	http://www.boost.org

install boost unit testing library:
        boost_installation_prefix=/usr
	cd $boost_path
	./bootstrap.sh
	sudo ./b2 --with-test --with-log --with-thread --with-container --with-program_options --prefix=$boost_installation_prefix install

make release
sudo bash install.bash

or
make all to also compile and install development and debug builds
