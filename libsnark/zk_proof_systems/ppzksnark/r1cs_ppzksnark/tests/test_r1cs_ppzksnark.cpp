/** @file
 *****************************************************************************
 Test program that exercises the ppzkSNARK (first generator, then
 prover, then verifier) on a synthetic R1CS instance.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

using namespace libsnark;

string get_random_str(int len){
    string str = "";
    for (int i = 0; i < len; i ++) {
        str += 'a' + rand() % 26;
    }
    return str;
}

template<typename ppT>
void test_r1cs_ppzksnark(int la, int ra, int lb, int rb, int lenc)
{
    libff::print_header("(enter) Test R1CS ppzkSNARK");

    const bool test_serialization = true;
    string c1 = get_random_str(lenc), c2 = c1;
    string a = get_random_str(la) + c1 + get_random_str(ra);
    string b = get_random_str(lb) + c2 + get_random_str(rb);

    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_sha2<libff::Fr<ppT> >(a, b, la, la+lenc, lb, lb+lenc);
    //generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool bit = run_r1cs_ppzksnark<ppT>(example, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test R1CS ppzkSNARK");
}

template<typename ppT>
void test_r1cs_ppzksnark_limit_len(int la, int ra, int lb, int rb, int lenc, int limit)
{
    libff::print_header("(enter) Test R1CS ppzkSNARK");

    const bool test_serialization = true;
    string c1 = get_random_str(lenc), c2 = c1;
    string a = get_random_str(la) + c1 + get_random_str(ra);
    string b = get_random_str(lb) + c2 + get_random_str(rb);

    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_sha2_limit_len<libff::Fr<ppT> >(a, b, la, la+lenc, lb, lb+lenc, limit);
    //generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool bit = run_r1cs_ppzksnark<ppT>(example, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test R1CS ppzkSNARK");
}

int main()
{
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();
    vector<double> times;
    char buffer[100000];
    char *ptr = buffer;
    int m = 20 - 1;
    for (int len = 5; len <= 5; len ++) {
        times.clear();
        int lenc = len;
        int la = rand() % (len * m + 1), ra = len * m - la;
//        int lb = rand() % (len * m + 1), rb = len * m - la;
        int lb = 0, rb = 0;
        int limit = la + ra + lenc;
        for (int i = 0; i < 1; i++) {
            // len_a = la + ra + len_c, len_b = lb + rb + len_c
            test_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(la, ra, lb, rb, lenc);
//            test_r1cs_ppzksnark_limit_len<default_r1cs_ppzksnark_pp>(la, ra, lb, rb, lenc, limit);
            double x = libff::last_times["Call to run_r1cs_ppzksnark"] * 1e-9;
            //        printf("[%0.4fs]", x);
            times.push_back(x);
            libff::clear_profiling_counters();
        }
        ptr += sprintf(ptr, "len=%d\n", len);
        double sum = 0.0, sum2 = 0.0;
        for (int i = 0; i < times.size(); i++) {
            ptr += sprintf(ptr, "[%0.4fs]\n", times[i]);
            sum += times[i];
            sum2 += times[i] * times[i];
        }
        double avg = sum / times.size(), avg2 = sum2 / times.size();
        double var = avg2 - avg * avg, std = sqrt(var);
        ptr += sprintf(ptr, "avg=%lf var=%lf std=%lf\n", avg, var, std);
    }
    printf("%s\n", buffer);
}
