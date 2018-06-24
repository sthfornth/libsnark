/** @file
 *****************************************************************************

 Implementation of functions to sample R1CS examples with prescribed parameters
 (according to some distribution).

 See r1cs_examples.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_EXAMPLES_TCC_
#define R1CS_EXAMPLES_TCC_

#include <cassert>

#include <libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/common/string_to_bits.h>

namespace libsnark {

template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_field_input(const size_t num_constraints,
                                                            const size_t num_inputs)
{
    libff::enter_block("Call to generate_r1cs_example_with_field_input");

    assert(num_inputs <= num_constraints + 2);

    r1cs_constraint_system<FieldT> cs;
    cs.primary_input_size = num_inputs;
    cs.auxiliary_input_size = 2 + num_constraints - num_inputs; // TODO: explain this

    r1cs_variable_assignment<FieldT> full_variable_assignment;
    FieldT a = FieldT::random_element();
    FieldT b = FieldT::random_element();
    full_variable_assignment.push_back(a);
    full_variable_assignment.push_back(b);

    for (size_t i = 0; i < num_constraints-1; ++i)
    {
        linear_combination<FieldT> A, B, C;

        if (i % 2)
        {
            // a * b = c
            A.add_term(i+1, 1);
            B.add_term(i+2, 1);
            C.add_term(i+3, 1);
            FieldT tmp = a*b;
            full_variable_assignment.push_back(tmp);
            a = b; b = tmp;
        }
        else
        {
            // a + b = c
            B.add_term(0, 1);
            A.add_term(i+1, 1);
            A.add_term(i+2, 1);
            C.add_term(i+3, 1);
            FieldT tmp = a+b;
            full_variable_assignment.push_back(tmp);
            a = b; b = tmp;
        }

        cs.add_constraint(r1cs_constraint<FieldT>(A, B, C));
    }

    linear_combination<FieldT> A, B, C;
    FieldT fin = FieldT::zero();
    for (size_t i = 1; i < cs.num_variables(); ++i)
    {
        A.add_term(i, 1);
        B.add_term(i, 1);
        fin = fin + full_variable_assignment[i-1];
    }
    C.add_term(cs.num_variables(), 1);
    cs.add_constraint(r1cs_constraint<FieldT>(A, B, C));
    full_variable_assignment.push_back(fin.squared());

    /* split variable assignment */
    r1cs_primary_input<FieldT> primary_input(full_variable_assignment.begin(), full_variable_assignment.begin() + num_inputs);
    r1cs_primary_input<FieldT> auxiliary_input(full_variable_assignment.begin() + num_inputs, full_variable_assignment.end());

    /* sanity checks */
    assert(cs.num_variables() == full_variable_assignment.size());
    assert(cs.num_variables() >= num_inputs);
    assert(cs.num_inputs() == num_inputs);
    assert(cs.num_constraints() == num_constraints);
    assert(cs.is_satisfied(primary_input, auxiliary_input));

    libff::leave_block("Call to generate_r1cs_example_with_field_input");

    return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
}

template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_binary_input(const size_t num_constraints,
                                                             const size_t num_inputs)
{
    libff::enter_block("Call to generate_r1cs_example_with_binary_input");

    assert(num_inputs >= 1);

    r1cs_constraint_system<FieldT> cs;
    cs.primary_input_size = num_inputs;
    cs.auxiliary_input_size = num_constraints; /* we will add one auxiliary variable per constraint */

    r1cs_variable_assignment<FieldT> full_variable_assignment;
    for (size_t i = 0; i < num_inputs; ++i)
    {
        full_variable_assignment.push_back(FieldT(std::rand() % 2));
    }

    size_t lastvar = num_inputs-1;
    for (size_t i = 0; i < num_constraints; ++i)
    {
        ++lastvar;
        const size_t u = (i == 0 ? std::rand() % num_inputs : std::rand() % i);
        const size_t v = (i == 0 ? std::rand() % num_inputs : std::rand() % i);

        /* chose two random bits and XOR them together:
           res = u + v - 2 * u * v
           2 * u * v = u + v - res
        */
        linear_combination<FieldT> A, B, C;
        A.add_term(u+1, 2);
        B.add_term(v+1, 1);
        if (u == v)
        {
            C.add_term(u+1, 2);
        }
        else
        {
            C.add_term(u+1, 1);
            C.add_term(v+1, 1);
        }
        C.add_term(lastvar+1, -FieldT::one());

        cs.add_constraint(r1cs_constraint<FieldT>(A, B, C));
        full_variable_assignment.push_back(full_variable_assignment[u] + full_variable_assignment[v] - full_variable_assignment[u] * full_variable_assignment[v] - full_variable_assignment[u] * full_variable_assignment[v]);
    }

    /* split variable assignment */
    r1cs_primary_input<FieldT> primary_input(full_variable_assignment.begin(), full_variable_assignment.begin() + num_inputs);
    r1cs_primary_input<FieldT> auxiliary_input(full_variable_assignment.begin() + num_inputs, full_variable_assignment.end());

    /* sanity checks */
    assert(cs.num_variables() == full_variable_assignment.size());
    assert(cs.num_variables() >= num_inputs);
    assert(cs.num_inputs() == num_inputs);
    assert(cs.num_constraints() == num_constraints);
    assert(cs.is_satisfied(primary_input, auxiliary_input));

    libff::leave_block("Call to generate_r1cs_example_with_binary_input");

    return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
}

template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_sha2(string a, string b, int a1, int a2, int b1, int b2)
{
    libff::enter_block("Call to generate_r1cs_example_with_sha2");

    //digitize the string and padding
    libff::bit_vector atext = string_to_bits_with_padding(a);
    libff::bit_vector btext = string_to_bits_with_padding(b);
    libff::bit_vector text = atext;
    text.insert(text.end(), btext.begin(), btext.end());

    protoboard<FieldT> pb;

    size_t r1cs_input_size = 512;
    pb_variable_array<FieldT> r1cs_input;
    r1cs_input.allocate(pb, r1cs_input_size, "r1cs_input");
    pb.set_input_sizes(r1cs_input_size);
    pb_variable_array<FieldT> text_input;
    text_input.allocate(pb, text.size(), "text_input");
    text_input.fill_with_bits(pb, text);

    a1 *= 8, a2 *= 8, b1 *= 8, b2 *= 8;
    assert (a2 - a1 == b2 - b1);
    for (int i = 0; i < a2 - a1; ++i) {
        pb_linear_combination<FieldT> B, C;
        B.add_term(r1cs_input_size + a1 + i + 1, 1);
        C.add_term(r1cs_input_size + atext.size() + b1 + i + 1, 1);
        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
    }

    libff::bit_vector ahash = sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, atext);
    libff::bit_vector bhash = sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, btext);
    libff::bit_vector input_bits = ahash;
    input_bits.insert(input_bits.end(), bhash.begin(), bhash.end());
    r1cs_input.fill_with_bits(pb, input_bits);

    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
//    printf("%d\n", cs.constraints.size());
    r1cs_variable_assignment<FieldT> full_variable_assignment = pb.full_variable_assignment();
//    printf("%d\n", full_variable_assignment.size());
    r1cs_primary_input<FieldT> primary_input = pb.primary_input();
//    printf("%d\n", primary_input.size());
    r1cs_primary_input<FieldT> auxiliary_input = pb.auxiliary_input();

    /* sanity checks */
    assert(cs.num_variables() == full_variable_assignment.size());
//    assert(cs.is_satisfied(primary_input, auxiliary_input));

    libff::leave_block("Call to generate_r1cs_example_with_sha2");

    return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
}


template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_sha2_limit_len(string a, string b, int a1, int a2, int b1, int b2, int limit)
{
    libff::enter_block("Call to generate_r1cs_example_with_sha2");

    while (a.size() <= limit)
        a += char(96);

    //digitize the string and padding
    libff::bit_vector atext = string_to_bits_with_padding(a);
    libff::bit_vector btext = string_to_bits_with_padding(b);
    libff::bit_vector text = atext;
    text.insert(text.end(), btext.begin(), btext.end());

    protoboard<FieldT> pb;

    size_t r1cs_input_size = 512;
    pb_variable_array<FieldT> r1cs_input;
    r1cs_input.allocate(pb, r1cs_input_size, "r1cs_input");
    pb.set_input_sizes(r1cs_input_size);
    pb_variable_array<FieldT> text_input;
    text_input.allocate(pb, text.size(), "text_input");
    text_input.fill_with_bits(pb, text);

    a1 *= 8, a2 *= 8, b1 *= 8, b2 *= 8;
    assert (a2 - a1 == b2 - b1);
    for (int i = 0; i < a2 - a1; ++i) {
        pb_linear_combination<FieldT> B, C;
        B.add_term(r1cs_input_size + a1 + i + 1, 1);
        C.add_term(r1cs_input_size + atext.size() + b1 + i + 1, 1);
        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
    }
    for (int i = 0; i < 8; ++ i){
        int pos = limit * 8 + i, val = int(i == 1 or i == 2);
        pb_linear_combination<FieldT> B, C;
        B.add_term(r1cs_input_size + pos + 1, 1);
        C.add_term(0, val);
        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
    }

    libff::bit_vector ahash = sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, atext);
    libff::bit_vector bhash = sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, btext);
    libff::bit_vector input_bits = ahash;
    input_bits.insert(input_bits.end(), bhash.begin(), bhash.end());
    r1cs_input.fill_with_bits(pb, input_bits);

    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
//    printf("%d\n", cs.constraints.size());
    r1cs_variable_assignment<FieldT> full_variable_assignment = pb.full_variable_assignment();
//    printf("%d\n", full_variable_assignment.size());
    r1cs_primary_input<FieldT> primary_input = pb.primary_input();
//    printf("%d\n", primary_input.size());
    r1cs_primary_input<FieldT> auxiliary_input = pb.auxiliary_input();

    /* sanity checks */
    assert(cs.num_variables() == full_variable_assignment.size());
//    assert(cs.is_satisfied(primary_input, auxiliary_input));

    libff::leave_block("Call to generate_r1cs_example_with_sha2");

    return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
}


template<typename FieldT>
void add_length_constraint_with_pb(protoboard<FieldT> &pb, string a, int lowerbound, int upperbound){
    if(lowerbound >= 1 && a.size() < lowerbound){
        while (a.size() <= lowerbound)
            a += char(96);
    }else if(upperbound > 1 && a.size() >= upperbound){
        while (a.size() <= upperbound)
            a += char(96);
    }

    //digitize the string and padding
    libff::bit_vector atext = string_to_bits_with_padding(a);
    libff::bit_vector text = atext;
    size_t r1cs_input_size = 512;

//    for (int i = 0; i < 8; ++ i){
//        int pos = lowerbound * 8 + i, val = int(i == 1 or i == 2);
//        pb_linear_combination<FieldT> B, C;
//        B.add_term(r1cs_input_size + pos + 1, 1);
//        C.add_term(0, val);
//        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
//    }

    for (int i = 0; i < 8; ++ i){
        int pos = upperbound * 8 + i, val = int(i == 1 or i == 2);
        pb_linear_combination<FieldT> B, C;
        B.add_term(r1cs_input_size + pos + 1, 1);
        C.add_term(0, val);
        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
    }

}



template<typename FieldT>
void add_substring_constraint_with_pb(protoboard<FieldT> &pb, int a1, int a2, int b1, int b2, size_t r1cs_input_size){
    for (int i = 0; i < a2 - a1; ++i) {
        pb_linear_combination<FieldT> B, C;
        B.add_term(r1cs_input_size + a1 + i + 1, 1);
        C.add_term(r1cs_input_size + b1 + i + 1, 1);
        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
    }

}

template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example(vector<string> s, vector<pair<int, int> > limit, vector<pair<int, int> > range) {
    libff::enter_block("Call to generate_r1cs_example_with_xxx");
    size_t n = s.size();

    for(int i = 0; i < n; i ++){
        if(limit[i].second > 0){
            while (limit[i].second > s[i].size())
                s[i] += char(96);
        }
    }

    //digitize the string and padding
    libff::bit_vector text;
    text.clear();
    for(int i = 0; i < n; i ++) {
        libff::bit_vector itext = string_to_bits_with_padding(s[i]);
        text.insert(text.end(), itext.begin(), itext.end());
    }

    protoboard<FieldT> pb;

    size_t r1cs_input_size = 256 * n;
    pb_variable_array<FieldT> r1cs_input;
    r1cs_input.allocate(pb, r1cs_input_size, "r1cs_input");
    pb.set_input_sizes(r1cs_input_size);
    pb_variable_array<FieldT> text_input;
    text_input.allocate(pb, text.size(), "text_input");
    text_input.fill_with_bits(pb, text);


    size_t a1 = 8 * range[0].first, a2 = 8 * range[0].second;
    size_t prev = 0;
    libff::bit_vector input_bits;
    input_bits.clear();
    for (int i = 0; i < n; i ++){
        if(i != 0){//add substring constraint
            size_t b1 = 8 * range[i].first, b2 = 8 * range[i].second;
            for (int j = 0; j < a2 - a1; j ++) {
                pb_linear_combination<FieldT> B, C;
                B.add_term(r1cs_input_size + a1 + i + 1, 1);
                C.add_term(r1cs_input_size + prev + b1 + i + 1, 1);
                pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
            }
        }
        //add length constraint
        if (limit[i].second >= 0)
            for (int j = 0; j < 8; j ++){
                int pos = prev + limit[i].second * 8 + j - 8, val = int(j == 1 or j == 2);
                pb_linear_combination<FieldT> B, C;
                B.add_term(r1cs_input_size + pos + 1, 1);
                C.add_term(0, val);
                pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
            }

        libff::bit_vector itext = string_to_bits_with_padding(s[i]);
        libff::bit_vector ihash = sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, itext);
        input_bits.insert(input_bits.end(), ihash.begin(), ihash.end());
        prev += itext.size();
    }

    r1cs_input.fill_with_bits(pb, input_bits);


    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
//    printf("%d\n", cs.constraints.size());
    r1cs_variable_assignment<FieldT> full_variable_assignment = pb.full_variable_assignment();
//    printf("%d\n", full_variable_assignment.size());
    r1cs_primary_input<FieldT> primary_input = pb.primary_input();
//    printf("%d\n", primary_input.size());
    r1cs_primary_input<FieldT> auxiliary_input = pb.auxiliary_input();

    /* sanity checks */
    assert(cs.num_variables() == full_variable_assignment.size());
//    assert(cs.is_satisfied(primary_input, auxiliary_input));

    libff::leave_block("Call to generate_r1cs_example_with_xxx");

    return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));

}

//template<typename FieldT>
//r1cs_example<FieldT> generate_r1cs_example_with_sha2_multistring(vector<string> s, vector<int> l, vector<int> r)
//{
//    libff::enter_block("Call to generate_r1cs_example_with_sha2");
//    assert(s.size() == l.size() && s.size() == r.size());
//    int n = s.size();
//    for(int i = 0; i < n; i ++){
//
//    }
//    //digitize the string and padding
//    libff::bit_vector atext = string_to_bits_with_padding(a);
//    libff::bit_vector btext = string_to_bits_with_padding(b);
//    libff::bit_vector text = atext;
//    text.insert(text.end(), btext.begin(), btext.end());
//
//    protoboard<FieldT> pb;
//
//    size_t r1cs_input_size = 512;
//    pb_variable_array<FieldT> r1cs_input;
//    r1cs_input.allocate(pb, r1cs_input_size, "r1cs_input");
//    pb.set_input_sizes(r1cs_input_size);
//    pb_variable_array<FieldT> text_input;
//    text_input.allocate(pb, text.size(), "text_input");
//    text_input.fill_with_bits(pb, text);
//
//    a1 *= 8, a2 *= 8, b1 *= 8, b2 *= 8;
//    assert (a2 - a1 == b2 - b1);
//    for (int i = 0; i < a2 - a1; ++i) {
//        pb_linear_combination<FieldT> B, C;
//        B.add_term(r1cs_input_size + a1 + i + 1, 1);
//        C.add_term(r1cs_input_size + atext.size() + b1 + i + 1, 1);
//        pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, B, C));
//    }
//    int bound;
//    assert(s[0].size() < bound);
//
//
//    libff::bit_vector ahash = sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, atext);
//    libff::bit_vector bhash = sha256_two_to_one_hash_gadget<FieldT>::get_hash_and_generate_constraint_with_pb(pb, btext);
//    libff::bit_vector input_bits = ahash;
//    input_bits.insert(input_bits.end(), bhash.begin(), bhash.end());
//    r1cs_input.fill_with_bits(pb, input_bits);
//
//    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();
////    printf("%d\n", cs.constraints.size());
//    r1cs_variable_assignment<FieldT> full_variable_assignment = pb.full_variable_assignment();
////    printf("%d\n", full_variable_assignment.size());
//    r1cs_primary_input<FieldT> primary_input = pb.primary_input();
////    printf("%d\n", primary_input.size());
//    r1cs_primary_input<FieldT> auxiliary_input = pb.auxiliary_input();
//
//    /* sanity checks */
//    assert(cs.num_variables() == full_variable_assignment.size());
//    assert(cs.is_satisfied(primary_input, auxiliary_input));
//
//    libff::leave_block("Call to generate_r1cs_example_with_sha2");
//
//    return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
//}


} // libsnark

#endif // R1CS_EXAMPLES_TCC
