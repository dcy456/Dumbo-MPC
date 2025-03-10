#!/bin/bash

# Clone the zfec repository
git clone https://github.com/tahoe-lafs/zfec.git

# Navigate to the zfec directory
cd zfec || exit

# Modify setup.py to change -march=x86-64-v2 to -march=x86-64
sed -i 's/-march=x86-64-v2/-march=x86-64/' setup.py

# Install the package
pip install .

echo "zfec has been installed successfully."