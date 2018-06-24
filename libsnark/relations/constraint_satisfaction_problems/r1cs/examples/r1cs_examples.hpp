/** @file
 *****************************************************************************

 Declaration of interfaces for a R1CS example, as well as functions to sample
 R1CS examples with prescribed parameters (according to some distribution).

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_EXAMPLES_HPP_
#define R1CS_EXAMPLES_HPP_

#include <iostream>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
using namespace std;

namespace libsnark {

/**
 * A R1CS example comprises a R1CS constraint system, R1CS input, and R1CS witness.
 */
template<typename FieldT>
struct r1cs_example {
    r1cs_constraint_system<FieldT> constraint_system;
    r1cs_primary_input<FieldT> primary_input;
    r1cs_auxiliary_input<FieldT> auxiliary_input;

    r1cs_example<FieldT>() = default;
    r1cs_example<FieldT>(const r1cs_example<FieldT> &other) = default;
    r1cs_example<FieldT>(const r1cs_constraint_system<FieldT> &constraint_system,
                         const r1cs_primary_input<FieldT> &primary_input,
                         const r1cs_auxiliary_input<FieldT> &auxiliary_input) :
        constraint_system(constraint_system),
        primary_input(primary_input),
        auxiliary_input(auxiliary_input)
    {};
    r1cs_example<FieldT>(r1cs_constraint_system<FieldT> &&constraint_system,
                         r1cs_primary_input<FieldT> &&primary_input,
                         r1cs_auxiliary_input<FieldT> &&auxiliary_input) :
        constraint_system(std::move(constraint_system)),
        primary_input(std::move(primary_input)),
        auxiliary_input(std::move(auxiliary_input))
    {};
};

/**
 * Generate a R1CS example such that:
 * - the number of constraints of the R1CS constraint system is num_constraints;
 * - the number of variables of the R1CS constraint system is (approximately) num_constraints;
 * - the number of inputs of the R1CS constraint system is num_inputs;
 * - the R1CS input consists of ``full'' field elements (typically require the whole log|Field| bits to represent).
 */
template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_field_input(const size_t num_constraints,
                                                            const size_t num_inputs);

/**
 * Generate a R1CS example such that:
 * - the number of constraints of the R1CS constraint system is num_constraints;
 * - the number of variables of the R1CS constraint system is (approximately) num_constraints;
 * - the number of inputs of the R1CS constraint system is num_inputs;
 * - the R1CS input consists of binary values (as opposed to ``full'' field elements).
 */
template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_binary_input(const size_t num_constraints,
                                                             const size_t num_inputs);

/**
 * Generate a R1CS example such that:
 * a[a1:a2] == b[b1:b2]
 */
template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_sha2(string a, string b, int a1, int a2, int b1, int b2);

/**
 * Generate a R1CS example such that:
 * a[a1:a2] == b[b1:b2] and len(a) <= limit
 */
template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example_with_sha2_limit_len(string a, string b, int a1, int a2, int b1, int b2, int limit);

template<typename FieldT>
r1cs_example<FieldT> generate_r1cs_example(vector<string> s, vector<pair<int, int> > limit, vector<pair<int, int> > range);


//template<typename FieldT>
//r1cs_example<FieldT> generate_r1cs_example_with_sha2_multistring(string a, string b, int a1, int a2, int b1, int b2);

} // libsnark

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.tcc>

#endif // R1CS_EXAMPLES_HPP_
