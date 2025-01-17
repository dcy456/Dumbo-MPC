
import json, os
        

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', metavar='N', required=True,
                        help='number of parties', type=int)
    
    parser.add_argument('--k', metavar='k', required=True,
                        help='batch size', type=int)
    args = parser.parse_args()
    
    N = args.N
    k = args.k
    
    for i in range(N):
        filename = f'conf/mpc_{N}/local.{i}.json'
        
        with open(filename, 'r') as json_file:
            data = json.load(json_file)

        data['extra']['k'] = k


        with open(filename, 'w') as json_file:
            json.dump(data, json_file, indent=4)
    
