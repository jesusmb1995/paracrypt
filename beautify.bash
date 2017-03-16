#!/bin/bash
# execute with "bash beautify.bash"
shopt -s extglob

# Kernighan and Ritchie style
indent -kr src/*.@(c|cpp|cu|h|hpp|cuh)
indent -kr src/test/*.@(c|cpp|cu|h|hpp|cuh)
