from pytest import mark
from optimizedhbmpc.preprocessing import PreProcessedElements
from optimizedhbmpc.preprocessing import PreProcessingConstants as Constants
from math import log
import argparse
import sys

def get_butterfly_network_preprocess(n, t, k):
    num_switches = k * int(log(k, 2)) ** 2
    pp_elements = PreProcessedElements()
    pp_elements.generate_one_minus_ones(num_switches, n, t)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', required=True, help='number of parties', type=int)
    parser.add_argument('--k', required=True, help='batchsize', type=int)

    args = parser.parse_args()

    N = args.N
    f = int((N-1)/3)
    k = args.k

    get_butterfly_network_preprocess(N, f, k)