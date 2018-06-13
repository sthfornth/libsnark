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
r1cs_example<FieldT> generate_r1cs_example_with_sha2(string a, string b, int a1, int a2, int b1, int b2, const size_t num_constraints,
                                                             const size_t num_inputs)
{
    libff::enter_block("Call to generate_r1cs_example_with_sha2");

    assert(num_inputs >= 1);

    //digitize the string and padding
    int a1_ = a1 * 8;
    libff::bit_vector atext = libff::string_to_bits_with_padding(a);
    libff::bit_vector btext = libff::string_to_bits_with_padding(b);
    libff::bit_vector ahash = sha256_two_to_one_hash_gadget<FieldT>::get_hash(atext);
    libff::bit_vector bhash = sha256_two_to_one_hash_gadget<FieldT>::get_hash(btext);
    sha256_two_to_one_hash_gadget<FieldT> agadget = sha256_two_to_one_hash_gadget<FieldT>::get_gadget(atext);
    sha256_two_to_one_hash_gadget<FieldT> bgadget = sha256_two_to_one_hash_gadget<FieldT>::get_gadget(btext);
//    for (int i = 0; i < atext.size(); ++ i){
//        printf("%d ", int(atext[i]));
//    }
//    puts("");
    agadget.generate_r1cs_constraints();


    r1cs_constraint_system<FieldT> cs;
    cs.primary_input_size = ahash.size() + bhash.size();
    cs.auxiliary_input_size = atext.size() + btext.size(); /* we will add one auxiliary variable per constraint */

    r1cs_variable_assignment<FieldT> full_variable_assignment;
    // ahash -> full_variable_assignment
    // bhash -> full_variable_assignment
    // atext -> full_variable_assignment
    // btext -> full_variable_assignment

//    for (size_t i = 0; i < num_inputs; ++i)
//    {
//        full_variable_assignment.push_back(FieldT(std::rand() % 2));
//    }

//    size_t lastvar = num_inputs-1;
//    for (size_t i = 0; i < num_constraints; ++i)
//    {
//        ++lastvar;
//        const size_t u = (i == 0 ? std::rand() % num_inputs : std::rand() % i);
//        const size_t v = (i == 0 ? std::rand() % num_inputs : std::rand() % i);
//
//        /* chose two random bits and XOR them together:
//           res = u + v - 2 * u * v
//           2 * u * v = u + v - res
//        */
//        linear_combination<FieldT> A, B, C;
//        A.add_term(u+1, 2);
//        B.add_term(v+1, 1);
//        if (u == v)
//        {
//            C.add_term(u+1, 2);
//        }
//        else
//        {
//            C.add_term(u+1, 1);
//            C.add_term(v+1, 1);
//        }
//        C.add_term(lastvar+1, -FieldT::one());
//
//        cs.add_constraint(r1cs_constraint<FieldT>(A, B, C));
//        full_variable_assignment.push_back(full_variable_assignment[u] + full_variable_assignment[v] - full_variable_assignment[u] * full_variable_assignment[v] - full_variable_assignment[u] * full_variable_assignment[v]);
//    }

    assert (a2 - a1 == b2 - b1);
    for (size_t i = 0; i < a2 - a1; ++i) {
        linear_combination<FieldT> B, C;
        B.add_term(cs.primary_input_size + a1 + i + 1, 1);
        C.add_term(cs.primary_input_size + atext.size() + b1 + i + 1, 1);
        cs.add_constraint(r1cs_constraint<FieldT>(1, B, C));
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

    libff::leave_block("Call to generate_r1cs_example_with_sha2");

    return r1cs_example<FieldT>(std::move(cs), std::move(primary_input), std::move(auxiliary_input));
}


} // libsnark

#endif // R1CS_EXAMPLES_TCC
