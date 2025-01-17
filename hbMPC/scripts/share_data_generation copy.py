from honeybadgermpc.preprocessing import PreProcessedElements
from honeybadgermpc.preprocessing import PreProcessingConstants as Constants
from math import log

def get_butterfly_network_preprocess(n, t, k):
    num_switches = k * int(log(k, 2)) ** 2
    pp_elements = PreProcessedElements()
    pp_elements.generate_triples(2 * num_switches, n, t)
    pp_elements.generate_one_minus_ones(num_switches, n, t)
    pp_elements.generate_rands(k, n, t)
    # for i in range(n):
    #     pp_elements.mixins[Constants.TRIPLES]._build_file_name(n, t, i)


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='f', required=True,
                        help='number of faulties', type=int)
    parser.add_argument('--k', metavar='k', required=True,
                        help='batchsize', type=int)


    args = parser.parse_args()

    N = args.N
    f = args.f
    k = args.k

    get_butterfly_network_preprocess(N, f, k)