//
// Created by xinyue on 6/23/18.
//

#ifndef LIBSNARK_STRING_TO_BITS_H
#define LIBSNARK_STRING_TO_BITS_H

#include <iostream>
#include <depends/libff/libff/common/utils.hpp>

using libff::bit_vector;
using std::string;

namespace libsnark {

bit_vector string_to_bits(string str, const size_t wordsize = 8);
bit_vector string_to_bits_with_padding(string str, const size_t chunk_size = 512, const size_t wordsize = 8);

}
#endif //LIBSNARK_STRING_TO_BITS_H
