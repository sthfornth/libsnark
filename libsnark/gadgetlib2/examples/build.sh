#!/bin/bash
set -e -x
g++ simple_example.cpp tutorial.cpp -o ./tutorial -I $ROOT -I $ROOT/depends -I $ROOT/build/install/include -L $ROOT/build/install/lib -lff -lsnark -std=c++11 -lgmp -lgmpxx -lzm -DCURVE_BN128 -lgtest -lsupercop -pthread -DBN_SUPPORT_SNARK
