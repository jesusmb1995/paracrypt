Website: paracrypt.bdevel.org

# Folder structure
* root directory
	- The GPU GPLv3 license in which Paracrypt is released can be found in the file COPYING. 
	- Makefile permits to build Paracrypt
	- Once Paracrypt has been built install.bash can copy the shared library, public header, and command line tool binary to the operative system directories.
* /doc/GPU-Accelerated-AES.pdf: Paracrypt paper
* /doc: References ordered by categories and classified in folders from 0_MostImportant to 2_LessImportant according the their importance.

* /bin: built binaries are stored here
* /inc: Paracrypt public header can be found here. Include this header in your own applications to use Paracrypt.
* /lib: built libparacrypt.so shared library is stored here
* /obj: generated objects during the compilation are stored here

* /proj: NVidia Nsight workspace folder

* /scripts: scripts that permit to generate performance results
* /info: generated documents such as performance data and plots are stored here

* /archive: Contains previous versions of the software. Please read NOTES.txt in each folder version to know what functionallity is working and what tests you can execute.

# Installation
Paracrypt compilation has been tested in Ubuntu.

## Installing Boost libraries
* Download boost from [boost.org](http://www.boost.org)
* Extract the contents at `boost_path="your path here"`
* Install the required libraries:
```bash
boost_installation_prefix=/usr
cd $boost_path
./bootstrap.sh
sudo ./b2 --with-test --with-log --with-thread --with-container --with-program_options --prefix=$boost_installation_prefix install
```
## Installing Paracrypt
* Compile Paracrypt library and command line tool `make release`
* Install paracrypt: `sudo bash install.bash` and answer `y`

# Usage
First, be sure the library path is set correctly. To set the library path to the default installation folder use:
```bash
LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH
```

To know how to use paracrypt type `paracrypt --help`

# Performance tests
Once Paracrypt is installed in the system, performance plots and tables can be generated with scripts/performances.bash:
```bash
cd scripts
bash performances.bash
```

# Unitary tests
Uncomment the building of tests in the Makefile. 

Change lines 294 and 295 from Makefile from this:
```bash
#builds: tests
builds: library tool
```

to this:
```bash
builds: tests
#builds: library tool
```

Then compile in debug or development mode to enable additional prints.
* To compile in debug mode: `make debug`
* To compile in development mode: `make devel`

You only need to execute Launcher tests to ensure the application is working fine because the Launcher uses all the other modules.
```bash
.bin/paracrypt_tests_dbg --run_test=LAUNCHERS
```


