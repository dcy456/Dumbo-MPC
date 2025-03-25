# Running Dumbo-MPC

Fully asynchronous multi-party computation (MPC) has superior robustness in realizing privacy and guaranteed output delivery (GOD) against asynchronous adversaries that can arbitrarily delay communications. We design an efficient fully asynchronous MPC—Dumbo-MPC with entire GOD and optimal resilience against 𝑡 < 𝑛/3 corruptions (where 𝑛 is the total number of parties). The codebase includes the implementation for Dumbo-MPC.

## Setup

To run the benchmarks at your machine (with Ubuntu 20.04 LTS), first install all dependencies as follows:

1. Install System Dependencies

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends make bison flex libgmp-dev libmpc-dev libntl-dev libflint-dev python3 python3-dev python3-pip libssl-dev wget git build-essential curl tmux
```

2. Install Python Dependencies
```bash
pip install cffi Cython gmpy2 pycryptodome pyzmq pyyaml psutil reedsolo numpy pytest
```

3. Install zfec
```bash
./install_zfec.sh
```


4. Install Rustup

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly
source $HOME/.cargo/env
rustup --version
export PATH="$HOME/.cargo/bin:$PATH"
```

5. Install pbc:

```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14
sudo ./configure
sudo make
sudo make install
cd ..
sudo ldconfig /usr/local/lib
```

6. Install Charm-Crypto:

```bash
git clone https://github.com/JHUISI/charm.git
cd charm
sudo ./configure.sh
sudo make 
sudo make install 
sudo make test
cd ..
```

7. Install pairing
```bash
cd dumbo-mpc/OptRanTriGen/pairing/
pip install --upgrade setuptools setuptools_rust
pip install .
cd ..
```

8. Install remaining pip dependencies here
```bash
sudo sed -i '30c #include "flint/flint.h"' /usr/include/flint/flintxx/flint_classes.h
pip install .
ln -sf /usr/bin/python3 /usr/bin/python
python setup.py build_ext --inplace

cd hbmpc/
python setup.py build_ext --inplace
```

## Running Dumbo-MPC at your local machine
1. A quick start to run Dumbo-MPC (where fast path (OptRanTriGen) and pessimistic path (AsyRanTriGen) are both with a batch size of 200)  for 4 nodes can be:
```bash
./run_local_network_test.sh dumbo-mpc 4 200
```
We simulate an check failure at a specific round (e.g., round 10) during the OptRanTriGen phase, and subsequently begin executing the AsyRanTriGen after secure fallback. The experiment logs are shown at `Dumbo-MPC/dumbo-mpc/dualmode/log`.

2. Run asy_random to generate random shares using AsyRanShGen algorithm:
```bash
./run_local_network_test.sh asy-random 4 200
```
The experiment logs are shown at `Dumbo-MPC/dumbo-mpc/AsyRanTriGen/log`.

3. Run asy_triple to generate Beaver triples using AsyRanTriGen algorithm:
```bash
./run_local_network_test.sh asy-triple 4 200
```
The experiment logs are shown at `Dumbo-MPC/dumbo-mpc/AsyRanTriGen/log`.

4. Run opt_triple to generate Beaver triples using OptRanTriGen algorithm:
```bash
./run_local_network_test.sh opt-triple 4 200
```
The experiment logs are shown at `Dumbo-MPC/dumbo-mpc/OptRanTriGen/log`.

5. Shuffle 16 inputs using butterfly network:

    First, Prepare random shares and Beaver Triples:
    ```bash
    cd Dumbo-MPC/dumbo-mpc/online
    ./preprocessing.sh 4 16
    ```
    All preprocessed data are stored at `dumbo-mpc/online/sharedata_test`.

    Then,  Execute the shuffle task: 
    ```bash
    ./scripts/local_test.sh butterfly_network.py 4 16
    ```

    The experiment logs are shown at `Dumbo-MPC/dumbo-mpc/online/log`.



5. Modify and build Cython code from gnark-crypto library

First, install go (>1.18). The code is built from the file `/gnark-crypto/kzg_ped_bls12-381/kzg_ped_out.go`. If you have to modify this code, please rebuild the Cython code. This can be done by running `./build_shared_library.sh` from `/gnark-crypto/kzg_ped_bls12-381/`.



## Running GS23 at your local machine
```bash
cd Dumbo-MPC/GS23
```
1. Generate random share:
```bash
./scripts/local_test.sh scripts/run_random.py 4 200
```
2. Generate beaver triple:
```bash
./scripts/local_test.sh scripts/run_beaver.py 4 200
```


## Running Dumbo-MPC on AWS

### 1. Setting up your AWS credentials

Set up your AWS credentials to enable programmatic access to your account from your local machine. These credentials will authorize your machine to create, delete, and edit instances on your AWS account programmatically. First of all, [find your 'access key id' and 'secret access key'](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-creds). Then, create a file `~/.aws/credentials` with the following content:

```bash
[default]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
```

### 2. Adding your SSH publlic key to your AWS account

You must now [add your SSH public key to your AWS account](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html). This operation is manual (AWS exposes little APIs to manipulate keys) and needs to be repeated for each AWS region that you plan to use. Upon importing your key, AWS requires you to choose a 'name' for your key; ensure you set the same name on all AWS regions. This SSH key will be used by the python scripts to execute commands and upload/download files to your AWS instances.If you don't have an SSH key, you can create one using [ssh-keygen](https://www.ssh.com/ssh/keygen/):

```bash
ssh-keygen -f ~/.ssh/aws
```

### 3. Deploying Dumbo-MPC on AWS

Launch an instance on AWS (with Ubuntu 20.04 LTS). If you are not familiar with AWS, you can visit Get started with Amazon EC2 Linux instances to get some help.To connect to the launched instance you, use SSH:

```bash
ssh -i your_ssh_key_path ubuntu@public_ip_of_instance
```

Then, upload codes of Dumbo-MPC into instance.

```bash
scp -i your_ssh_key_path -r DumboMPC_code_path ubuntu@public_ip_of_instance:~/
```

Then you should install dependencies according to the steps mentioned earlier.

Create an image using this instance. If you are not familiar with AWS, you can visit [Create an AMI from an Amazon EC2 Instance](https://docs.aws.amazon.com/toolkit-for-visual-studio/latest/user-guide/tkv-create-ami-from-instance.html) to get some help.

### 4. Running Dumbo-MPC on AWS

Run an AWS instance from the AMI and modify the `awsinit.sh` in `remote/ `.

```bash
cd remote
vim ./awsinit.sh
```

```bash
--image-id replace with your image id
--instance-type instance type, we recommend c6a.8xlarge or better
--key-name your ssh key name
--security-group-ids you can delete this option if you are not familiar with it
```

Then, start 4 instances:

```bash
./awsinit.sh 4
```

Run the Dumbo-MPC with a batch size of 5000 for 4 nodes:

```bash
cd Dumbo-MPC_scripts
./changeconfig.sh
./launch_dumboMPC.sh 4 5000
```

After benchmark, you can read the running results by connecting these instances and viewing these logs or by running `scplog.sh`.

```bash
./scplog.sh 4 5000
```

These logs will be stored in `./log_4_8x`.
