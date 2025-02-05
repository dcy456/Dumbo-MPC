import json
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def extract_random_share(field_modulus, degree, context_id, input_file_path, output_file_prefix):
    """Extract random share values and write them to a file.

    Parameters:
        field_modulus: Field modulus
        degree: Degree of the polynomial
        context_id: Context ID
        input_file_path: Path to the input file
        output_file_prefix: Prefix for output files
    """
    # Check and create output directory
    output_dir = os.path.dirname(output_file_prefix + '.share')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        # Read the JSON-like text stored in the specified input file
        with open(input_file_path, 'r') as infile:
            data = infile.read()

        # Parse JSON data
        parsed_data = json.loads(data)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read or parse file {input_file_path}: {e}")
        return

    # Extract ClaimedValue and ClaimedValueAux
    claimed_values = []
    claimed_value_auxs = []

    for item in parsed_data.get('proof', []):
        claimed_values.append(item.get('ClaimedValue'))
        claimed_value_auxs.append(item.get('ClaimedValueAux'))

    # Define output file paths
    claimed_values_file_path = f'{output_file_prefix}.share'
    claimed_value_auxs_file_path = f'{output_file_prefix}_aux.share'

    try:
        # Write to the specified output files, including metadata
        with open(claimed_values_file_path, 'w') as f:
            # Write metadata
            f.write(f"{field_modulus}\n{degree}\n{context_id}\n")
            # Write ClaimedValues
            for value in claimed_values:
                f.write(f"{value}\n")
                # f.write(value + '\n')

        # with open(claimed_value_auxs_file_path, 'w') as f:
        #     # Write metadata
        #     f.write(f"{field_modulus}\n{degree}\n{context_id}\n")
        #     # Write ClaimedValueAuxs
        #     for aux in claimed_value_auxs:
        #         f.write(aux + '\n')

        # logging.info(f"Random shares successfully written to files {claimed_values_file_path}.")
    except IOError as e:
        logging.error(f"Failed to write to files {claimed_values_file_path}: {e}")

def extract_triple(field_modulus, degree, context_id, input_file_path, output_file_prefix):
    """Extract triple from the given JSON file and write them in a cross format to an output file.

    Parameters:
        field_modulus: Field modulus
        degree: Degree of the polynomial
        context_id: Context ID
        input_file_path: Path to the input file
        output_file_prefix: Prefix for output files
    """
    try:
        # Read the JSON-like text stored in the specified input file
        with open(input_file_path, 'r') as infile:
            data = infile.read()

        # Parse JSON data
        parsed_data = json.loads(data)
        
        # Extract A, B, and C
        A = parsed_data.get("A", [])
        B = parsed_data.get("B", [])
        C = parsed_data.get("C", [])

        # Calculate minimum length to prevent index out of range
        min_length = min(len(A), len(B), len(C))

        # Define output file path
        output_file_path = f'{output_file_prefix}.share'

        # Write cross data to the output file
        with open(output_file_path, 'w') as outfile:
            outfile.write(f"{field_modulus}\n{degree}\n{context_id}\n")
            for i in range(min_length):
                outfile.write(f"{A[i]}\n{B[i]}\n{C[i]}\n")

        # logging.info(f"Triples successfully written to file {output_file_path}.")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Failed to read or parse file {input_file_path}: {e}")
    except IOError as e:
        logging.error(f"Failed to write to file {output_file_path}: {e}")

# Main program
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract random shares and triples")
    parser.add_argument('--N', type=int, required=True, help="Number of input files")
    # parser.add_argument('--t', type=int, required=True, help="Other parameter t")
    args = parser.parse_args()

    n = args.N
    t = int((n-1) /3)
    field_modulus = 52435875175126190479447740508185965837690552500527637822603658699938581184513

    for i in range(n):
        input_file_path = f'../AsyRanTriGen/ransh/{i}_randomshares.txt'

        output_file_prefix = f'./sharedata_test/rands_{n}_{t}-{i}'

        extract_random_share(field_modulus, t, i, input_file_path, output_file_prefix)

        input_file_path = f'../dualmode/asy-triples/{i}_triples.txt'

        output_file_prefix = f'./sharedata_test/triples_{n}_{t}-{i}'

        extract_triple(field_modulus, t, i, input_file_path, output_file_prefix)