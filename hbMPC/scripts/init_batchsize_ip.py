
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
    
    
    file_path = 'scripts/ip.txt'  

    with open(file_path, 'r') as file:
        
        ip_addresses = [line.strip() for line in file.readlines()[:N]]

    for i in range(N):
        port = 10000 + i * 200
        ip_addresses[i] = f"{ip_addresses[i]}:{port}"
    print("IP Addresses:")
    for ip in ip_addresses:
        print(ip)
    
    for i in range(N):
        filename = f'conf/mpc_{N}/local.{i}.json'
        
        with open(filename, 'r') as json_file:
            data = json.load(json_file)

        data['extra']['k'] = k
        data['peers'] = ip_addresses

        with open(filename, 'w') as json_file:
            json.dump(data, json_file, indent=4)
    
