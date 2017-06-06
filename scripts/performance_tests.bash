#!/bin/bash
# usage: bash performance_tests_core.bash performance_tests.bash [full-fast]
set -e
ulimit -u

# number of streams per gpu
performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=1" "_1-stream"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=2" "_2-stream"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=3" "_3-stream"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=4" "_4-stream"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=5" "_5-stream"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=8" "_8-stream"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=12" "_12-stream"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--stream-limit=1000" "_unlimited-streams"

# CPU-GPU stagging area / IO buffer size
performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=1" "_1MB-staging"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=2" "_2MB-staging"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=3" "_3MB-staging"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=4" "_4MB-staging"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=8" "_8MB-staging"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=16" "_16MB-staging"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=32" "_32MB-staging"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=64" "_64MB-staging"
#performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=128" "_128MB-staging"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--staging-area-limit=100000" "_unlimited-staging"

# constant vs non-constant GPU memory (16B parallelism)
performance "paracrypt" aes-128-ctr -e $key128 $iv "" "-16B" # (2)
performance "paracrypt" aes-128-ctr -e $key128 $iv "--disable-constant-key"                           "_16B-disabled-constant-key"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--disable-constant-tables"                        "_16B-disabled-constant-tables"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--disable-constant-key --disable-constant-tables" "_16B-disabled-constant-gpu-memory"

# out of order
# (2)
performance "paracrypt" aes-128-ctr -e $key128 $iv "--launch-out-of-order" "_out-of-order" 

# parallelism
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=8B" "-8B" # pointers vs ... (1)
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=4B" "-4B"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=1B" "-1B"

# constant vs non-constant GPU memory with 8B, 4B, and 1B parallelism
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=8B --disable-constant-key"                           "_8B-disabled-constant-key"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=8B --disable-constant-tables"                        "_8B-disabled-constant-tables"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=8B --disable-constant-key --disable-constant-tables" "_8B-disabled-constant-gpu-memory"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=4B --disable-constant-key"                           "_4B-disabled-constant-key"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=4B --disable-constant-tables"                        "_4B-disabled-constant-tables"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=4B --disable-constant-key --disable-constant-tables" "_4B-disabled-constant-gpu-memory"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=1B --disable-constant-key"                           "_1B-disabled-constant-key"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=1B --disable-constant-tables"                        "_1B-disabled-constant-tables"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=1B --disable-constant-key --disable-constant-tables" "_1B-disabled-constant-gpu-memory"

# parallelism with integer bitwise operators
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=16B --enable-integer-arithmetic" "-16B-integers" # ... (1) integer operators
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=8B --enable-integer-arithmetic" "-8B-integers"
performance "paracrypt" aes-128-ctr -e $key128 $iv "--parallelism=4B --enable-integer-arithmetic" "-4B-integers"

# modes of operation (decryption tests)
performance "paracrypt" aes-128-ecb -d $key128
performance "paracrypt" aes-128-ctr -d $key128 $iv
performance "paracrypt" aes-128-cbc -d $key128 $iv # (3)
performance "paracrypt" aes-128-cfb -d $key128 $iv # (4)

# ctr: openssl vs paracrypt
# (2)
performance "openssl" aes-128-ctr -e $key128 $iv

# cbc cfb decrypt: openssl vs paracrypt
# (3)
# (4)
performance "openssl" aes-128-cbc -d $key128 $iv "" "-decryption" "true"
performance "openssl" aes-128-cfb -d $key128 $iv "" "-decryption" "true"

# key size 
# (2)
performance "paracrypt" aes-192-ctr -e $key192 $iv "" "-16B" # (2)
performance "paracrypt" aes-256-ctr -e $key256 $iv "" "-16B" # (2)
performance "openssl" aes-192-ctr -e $key192 $iv
performance "openssl" aes-256-ctr -e $key256 $iv
