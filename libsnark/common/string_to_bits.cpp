//
// Created by xinyue on 6/23/18.
//

#include "string_to_bits.h"

bit_vector string_to_bits(string str, const size_t wordsize)
{
    bit_vector res(wordsize * str.size());
    for (size_t i = 0; i < str.size(); ++i)
    {
        int v = int(str[i]);
        for (size_t j = 0; j < wordsize; ++j)
            res[i*wordsize + j] = (v & (1<<(wordsize-1-j)));
    }
    return res;
}

bit_vector string_to_bits_with_padding(string str, const size_t chunk_size, const size_t wordsize)
{
    bit_vector res = string_to_bits(str, wordsize);
    unsigned long l = res.size();
    res.push_back(1);
    for (int i = 0; i < 64; i ++)
        res.push_back(bool(l & 1ul << (63 - i)));
    while (res.size() % chunk_size != 0)
        res.push_back(0);
    return res;
}
