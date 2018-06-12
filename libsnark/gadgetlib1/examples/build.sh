#!/bin/bash
set -e -x
g++ simple_example.tcc --shared -o ./tutorial -I $LIBSNARK/include -I $ROOT -L $LIBSNARK -lff -lsnark -lsnark_adsnark -std=c++11
