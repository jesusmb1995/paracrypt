#!/bin/bash
# execute with "bash beautify.bash"
shopt -s extglob

# Kernighan and Ritchie style
indent -kr src/*.@(c|cpp|cu|h|hpp|cuh)
indent -kr src/tests/*.@(cpp|hpp)
indent -kr src/openssl/reverse_ssl_internal_key.*
