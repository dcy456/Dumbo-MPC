from math import log
import argparse
import sys

def get_butterfly_network_preprocess(n, t, k):
    print(n, t, k)
    from honeybadgermpc.preprocessing import PreProcessedElements
    # from honeybadgermpc.preprocessing import PreProcessingConstants as Constants
    
    num_switches = k * int(log(k, 2)) ** 2
    # print("num_switches: ", num_switches)
    pp_elements = PreProcessedElements()
    pp_elements.generate_one_minus_ones(num_switches, n, t)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', required=True, help='number of parties', type=int)
    parser.add_argument('--k', required=True, help='batchsize', type=int)

    args = parser.parse_args()

    print(f"Number of parties: {args.N}")
    print(f"Batch size: {args.k}")
    
    N = args.N
    f = int((N-1)/3)
    k = args.k

    get_butterfly_network_preprocess(N, f, k)

if __name__ == "__main__":
    main()
