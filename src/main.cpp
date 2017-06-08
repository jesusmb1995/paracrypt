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

//////////////////////////////////////////////
//       PARACRYPT COMMAND LINE TOOL        //
//////////////////////////////////////////////

#include "Paracrypt.hpp"

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <iostream>
#include <iterator>
#include <string>
using namespace std;

#include "license_strings.cpp"

template<typename Out>
void split(const std::string &s, char delim, Out result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

// WARNING: caller have to use delete
// WARNING: hexstring length has to be odd
unsigned char* hexstring2array(string hexstring)
{
	size_t length = hexstring.size();
	assert(length % 2 == 0);
	const char *pos = hexstring.c_str();

	size_t bytes = length/2;
	unsigned char* val = new unsigned char[bytes];
	size_t count = 0;

	/* WARNING: no sanitization or error-checking whatsoever */
	for(count = 0; count < bytes; count++) {
	     sscanf(pos, "%2hhx", &val[count]);
	     pos += 2;
	}

	return val;
}

int main(int ac, char* av[])
{
	paracrypt::cipher_t c;
	paracrypt::operation_t op;
	string inFile, outFile;
	unsigned char* key;
	int key_bits;
	paracrypt::mode_t m;
	paracrypt::verbosity_t verbosity = paracrypt::WARNING;

    try {

    	string description =
    			string("GPU accelerated AES\n\n") +
    			notice +
    			string(
    				   "\n\nUse: paracrypt -c cipher (-e|-d)"
    				   " -K hexadecimal_key"
    				   " [-iv input_vector]"
    				   " -in input_file -out output_file"
    			) +
    			string("\n\nAllowed options");
    			// TODO more info./details about padding, what
    			//  ctr used in AES etc...

    	string cipherDecription =
    			"selects one of the following ciphers:"
    			" aes-128-ecb aes-256-ecb aes-192-ecb"
    			" aes-128-cbc aes-192-cbc aes-256-cbc"
    			" aes-128-cfb aes-192-cfb aes-256-cfb"
    			" aes-192-ctr aes-128-ctr aes-256-ctr";

    	string parallelism =
    			"set the level of paralelism "
    			" (if different implementations are available):\n"
    			"\tAvailable options for AES: 16B (default), 8B, 4B, 1B";

    	string verboseDecryption =
    			"level of verbosity: warning (default), info, debug, trace";


        po::options_description desc(description.c_str());
        desc.add_options()
		    // TODO group options in different sections
            ("help,h",                               "produce help message"                             )
            ("show",        po::value<string>(),     "show license warranty (w) or conditions (c)"      )
            ("quiet,q",                         "disables logging engine and do not output any messages")
            ("verbose,v",   po::value<string>(),     verboseDecryption.c_str()                          )

            // TODO group options in different sections
            ("cipher,c",    po::value<string>(),     cipherDecription.c_str()                           )
            ("encrypt,e",                            "encrypt input"                                    )
            ("decrypt,d",                            "decrypt input"                                    )
            ("Key,K",       po::value<string>(),     "hexadecimal key to be used directly by the cipher")
            ("iv",          po::value<string>(),     "specifies initialization vector in hexadecimal"   )
            ("in",          po::value<string>(),     "specifies the input file"                         )
            ("out",         po::value<string>(),     "specifies the output file"                        )
            ("parallelism", po::value<string>(),     parallelism.c_str()                                )

            // TODO the code for this options need slight adaptation when if we want to add support for other ciphers
            // TODO support different notations for staging-area-limit: MB, GB, KB, Bytes, etc.
            ("staging-area-limit", po::value<int>()->default_value(8),
             "maximum size (MiB) allowed for the pinned staging area between GPU and CPU (default: 8)")
            ("stream-limit",       po::value<int>()->default_value(4),
             "maximum number of concurrent kernels executing in each GPU (default: 4)")
            ("enable-integer-arithmetic", "use shift and xor bitwise operations to access individual bytes in the state")
            ("disable-constant-key", "don't use GPU constant memory to store AES round keys")
            ("disable-constant-tables", "don't use GPU constant memory to store AES lookup tables")
            ("launch-out-of-order", "do not necessarily wait for kernels in the same order they were launched")
        ;

        po::variables_map vm;
        int opt_style = ( // unix style - allow_guessing + allow_long_disguise
        		  po::command_line_style::allow_short
        		| po::command_line_style::short_allow_adjacent
        		| po::command_line_style::short_allow_next
        		| po::command_line_style::allow_long
        		| po::command_line_style::long_allow_adjacent
        		| po::command_line_style::long_allow_next
        		| po::command_line_style::allow_sticky
        	  //| po::command_line_style::allow_guessing // disabled guessing
                | po::command_line_style::allow_dash_for_short
                | po::command_line_style::allow_long_disguise // e.g. enable -in instead of --in
        );
        po::store(po::parse_command_line(ac, av, desc, opt_style), vm);
        po::notify(vm);

        if (vm.count("verbose") && vm.count("quiet")) {
    		cerr << "cannot be quiet and verbose at the same time\n";
    		return 1;
        }

        if (vm.count("quiet")) {
        	verbosity = paracrypt::QUIET;
        } else if (vm.count("verbose")) {
        	string logging_level = vm["verbose"].as<string>();
        	if(logging_level == "warning") {
        		verbosity = paracrypt::WARNING;
        	} else if(logging_level == "info") {
        		verbosity = paracrypt::INFO;
        	} else if(logging_level == "debug") {
        		verbosity = paracrypt::DBG;
        	} else if(logging_level == "trace") {
        		verbosity = paracrypt::TRACE;
        	} else {
        		cerr << "wrong argument for option verbose: use warning, info, debug, or trace\n";
        		return 1;
        	}
        }

        if (vm.count("help")) {
            cout << desc << "\n";
            return 0;
        }

        if (vm.count("show")) {
        	string what = vm["show"].as<string>();
        	if(what == "w") {
                cout << warranty;
        	}
        	else if(what == "c")  {
                cout << conditions;
        	}
        	else {
        		cerr << "wrong argument for option show: use 'c' or 'w'\n";
        		return 1;
        	}
            return 0;
        }

        if (vm.count("in")) {
        	inFile = vm["in"].as<string>();
        } else {
    		cerr << "input file required\n";
    		return 1;
        }

        if (vm.count("out")) {
        	outFile = vm["out"].as<string>();
        } else {
    		cerr << "output file required\n";
    		return 1;
        }

        if (vm.count("cipher")) {
        	string cipher = vm["cipher"].as<string>();
        	vector<string> cipherSpecs = split(cipher, '-');
        	if(cipherSpecs.size() != 3) {
        		cerr << "invalid cipher\n";
        		return 1;
        	}

        	if(cipherSpecs.at(0) == "aes") {
                if (vm.count("parallelism")) {
                	string parallelism = vm["parallelism"].as<string>();
                	if(parallelism == "16B") {
                		c = paracrypt::AES16B;
                	} else if(parallelism == "8B") {
                		c = paracrypt::AES8B;
                	} else if(parallelism == "4B") {
                		c = paracrypt::AES4B;
                	} else if(parallelism == "1B") {
                		c = paracrypt::AES1B;
                	} else {
                		cerr << "wrong argument for option parallelism\n";
                		return 1;
                	}
                } else {
                	c = paracrypt::AES16B;
                }

                string hexKey;
	        	if (vm.count("Key")) {
	        		hexKey = vm["Key"].as<string>();
	        	}
	        	else {
	        		cerr << "cipher key required\n";
	        		return 1;
	        	}

        		string keyBitsStr = cipherSpecs.at(1);
				if(keyBitsStr == "128") {
	        		if(hexKey.length() != 16*2) {
	            		cerr << "incorrect AES key length\n";
	            		return 1;
	        		}
					key_bits = 128;
				} else if(keyBitsStr == "192") {
	        		if(hexKey.length() != 24*2) {
	            		cerr << "incorrect AES key length\n";
	            		return 1;
	        		}
					key_bits = 192;
				} else if(keyBitsStr == "256") {
	        		if(hexKey.length() != 32*2) {
	            		cerr << "incorrect AES key length\n";
	            		return 1;
	        		}
					key_bits = 256;
				} else {
					cerr << "invalid cipher algorithm\n";
					return 1;
				}

				key = hexstring2array(hexKey);

				string modeStr = cipherSpecs.at(2);
				if(modeStr == "ecb") {
					m = paracrypt::ECB;
				} else if(modeStr == "cbc") {
					m = paracrypt::CBC;
				} else if(modeStr == "cfb") {
					m = paracrypt::CFB;
				} else if(modeStr == "ctr") {
					m = paracrypt::CTR;
				} else {
					cerr << "invalid cipher algorithm\n";
					return 1;
				}
        	} else {
        		cerr << "invalid cipher algorithm\n";
        		return 1;
        	}

        	if (vm.count("encrypt")) {
        		if( m == paracrypt::CBC || m == paracrypt::CFB) {
            		cerr << "Encryption is not supported in CBC and CFB modes."
            				" Use OpenSSL to encrypt and Paracrypt to decrypt.\n";
            		return 1;
        		}
        		op = paracrypt::ENCRYPT;
        	} else if(vm.count("decrypt")) {
        		op = paracrypt::DECRYPT;
        	}
        	else {
        		cerr << "operation required: use -e or -d\n";
        		return 1;
        	}
        } else {
    		cerr << "cipher option required\n";
    		return 1;
        }

    	paracrypt::config conf(c, op, inFile, outFile, key, key_bits, m);
    	conf.setVerbosity(verbosity);

    	unsigned char* iv = NULL;
    	if(vm.count("iv")) {
    		string hexiv = vm["iv"].as<string>();
    		if(hexiv.length() != 16*2) {
    			// TODO change when add support to other ciphers
    			//  here we dont check for other ciphers
        		cerr << "incorrect AES iv length\n";
        		return 1;
    		}
    		iv = hexstring2array(hexiv);
    		conf.setIV(iv, 128);
    	}
    	else if(m != paracrypt::ECB) {
    		cerr << "initialization vector (iv) required\n";
    		return 1;
    	}

    	if(vm.count("staging-area-limit")) {
    		int limit = vm["staging-area-limit"].as<int>();
    		if(limit < 0) {
        		cerr << "invalid negative staging-area-limit value\n";
        		return 1;
    		}
    		// MiB -> bytes
    		rlim_t bytes = limit * 1024 * 1024;
    		conf.staggingLimit(bytes);
    	}
    	if(vm.count("stream-limit")) {
    		int limit = vm["stream-limit"].as<int>();
    		if(limit < 0) {
        		cerr << "invalid negative stream-limit value\n";
        		return 1;
    		}
    		conf.streamLimit(limit);
    	}

    	// TODO change when add support to other ciphers
    	//  here we dont check for other ciphers and their
    	//  particular options
    	if(vm.count("disable-constant-key")) {
    		conf.disableConstantKey();
    	}
    	if(vm.count("disable-constant-tables")) {
    		conf.disableConstantTables();
    	}
    	if(vm.count("launch-out-of-order")) {
    		conf.enableOutOfOrder();
    	}
    	if(vm.count("enable-integer-arithmetic")) {
    		if(c == paracrypt::AES1B) {
        		cerr << "integer arithmetic not available with 1B parallelism\n";
        		return 1;
    		}
    		conf.enableBitwiseOperations();
    	}

    	paracrypt::exec(conf);

    	delete key;
    	if(iv != NULL)
    		delete iv;
    }
    catch(exception& e) {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }
    catch(...) {
        cerr << "Exception of unknown type!\n";
    }

    return 0;
}
