import re
import argparse

def extract_numbers(field_modulus, degree, context_id, input_file, output_file):
    """
    Extracts numbers enclosed in curly braces from the input file and appends them line by line to the output file.
    
    :param field_modulus: The modulus value to be included in the output file (field modulus)
    :param degree: The degree value to be included in the output file
    :param context_id: The context ID to be included in the output file
    :param input_file: The path of the input file containing numbers to be extracted
    :param output_file: The path of the output file where the extracted numbers will be saved
    """
    
    # Regular expression pattern to match numbers inside curly braces
    pattern = r"\{(\d+)\}"

    try:
        # Open the input file for reading and the output file for appending
        with open(input_file, 'r') as infile, open(output_file, 'a') as outfile:
            # Optionally, you can write the field modulus, degree, and context ID at the beginning of the file
            # If the file is being opened for the first time, you might want to add these at the top
            # We can write these only if the file is empty (this prevents writing them repeatedly)
            if outfile.tell() == 0:  # Check if file is empty
                outfile.write(f"{field_modulus}\n")
                outfile.write(f"{degree}\n")
                outfile.write(f"{context_id}\n")

            # Read each line in the input file
            for line in infile:
                # Find all numbers enclosed in curly braces in the current line
                matches = re.findall(pattern, line)
                
                # Write each matched number to the output file
                for match in matches:
                    outfile.write(match + '\n')

        print(f"Data has been successfully extracted and appended to {output_file}")
    
    except FileNotFoundError:
        print(f"Error: The file {input_file} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # Argument parsing for command-line input
    parser = argparse.ArgumentParser(description="Extract random shares and triples from input files")
    parser.add_argument('--N', type=int, required=True, help="Number of input files")
    # parser.add_argument('--t', type=int, required=True, help="Other parameter t")
    args = parser.parse_args()

    # Get the number of input files (N) from the command line argument
    n = args.N
    # Calculate the degree (t) based on the number of files (n)
    t = int((n-1) / 3)

    # The field modulus to be used (large integer for cryptographic purposes)
    field_modulus = 52435875175126190479447740508185965837690552500527637822603658699938581184513

    # Loop through each input file and call extract_numbers to process each one
    for i in range(n):
        # Construct the input file path based on the loop index
        input_file_path = f'../dualmode/opt-triples/{i}_triples.txt'
        
        # Construct the output file path based on the number of files (n), degree (t), and index (i)
        output_file = f'./sharedata_test/triples_{n}_{t}-{i}.share'
        
        # Call the function to extract numbers and append to the output file
        extract_numbers(field_modulus, t, i, input_file_path, output_file)
