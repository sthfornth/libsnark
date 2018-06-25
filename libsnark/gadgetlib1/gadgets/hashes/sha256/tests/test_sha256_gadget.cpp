/** @file
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include <libsnark/common/string_to_bits.h>

using namespace libsnark;

template<typename FieldT>
void test_two_to_one()
{
    protoboard<FieldT> pb;

    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();
    printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());

    const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
    const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);

    f.generate_r1cs_witness();
    output.generate_r1cs_witness(hash_bv);

    assert(pb.is_satisfied());
}


template<typename FieldT>
void test_two_to_one_flexible(int len)
{
    libff::enter_block("Call to test_two_to_one_flexible");
    protoboard<FieldT> pb;

//    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
//    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
//    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");
//
//    digest_variable<FieldT> input(pb, SHA256_digest_size, "input");
//
//    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
//    f.generate_r1cs_constraints();
//    printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());
//
//    const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
//    const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
//    const libff::bit_vector hash_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);
//
//    left.generate_r1cs_witness(left_bv);
//    right.generate_r1cs_witness(right_bv);
//
//    f.generate_r1cs_witness();
//    output.generate_r1cs_witness(hash_bv);
    std::string s;
    libff::bit_vector input;
    for (int i = 0; i < len; i ++)
        s.push_back(char(rand() % 128));
//    input = string_to_bits_with_padding(s);

    int wordsize = 8, chunk_size = 512;
    string str = s;
    bit_vector res(wordsize * str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        int v = int(str[i]);
        for (size_t j = 0; j < wordsize; ++j)
            res[i * wordsize + j] = (v & (1 << (wordsize - 1 - j)));
    }

    unsigned long l = res.size();
    res.push_back(1);
    for (int i = 0; i < 64; i++)
        res.push_back(bool(l & 1ul << (63 - i)));
    while (res.size() % chunk_size != 0)
        res.push_back(0);

    sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, res);

    assert(pb.is_satisfied());

    libff::leave_block("Call to test_two_to_one_flexible");
}



int main(void)
{
    libff::start_profiling();
    libff::default_ec_pp::init_public_params();
//    test_two_to_one<libff::Fr<libff::default_ec_pp> >();
//    for()
    test_two_to_one_flexible<libff::Fr<libff::default_ec_pp> >(600);
}
