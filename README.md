


## Prerequisites

```bash
# Install clang (as required by GONet to enable llvm_mode)
sudo apt-get install clang
# Install graphviz development
sudo apt-get install graphviz-dev libcap-dev
```

## GONet


```bash
# First, clone this GONet repository to a folder named GONet
git clone <links to the repository> GONet
# Then move to the source code folder
cd GONet
make clean all
cd llvm_mode
# The following make command may not work if llvm-config cannot be found
# To fix this issue, just set the LLVM_CONFIG env. variable to the specific llvm-config version on your machine
# On Ubuntu 18.04, it could be llvm-config-6.0 if you have installed clang using apt-get
make
# Move to GONet's parent folder
cd ../..
#Setup PATH environment variables
export GONet=$(pwd)/GONet
export WORKDIR=$(pwd)
export PATH=$PATH:$GONet
export GO_PATH=$GONet
```

# Usage

GONet has following options:

- ***-N netinfo***: server information (e.g., tcp://127.0.0.1/8554)

- ***-P protocol***: application protocol to be tested (e.g., RTSP, FTP, DTLS12, DNS, DICOM, SMTP, SSH, TLS, DAAP-HTTP, SIP)

- ***-D usec***: (optional) waiting time (in microseconds) for the server to complete its initialization 

- ***-e netnsname***: (optional) network namespace name to run the server in

- ***-K*** : (optional) send SIGTERM signal to gracefully terminate the server after consuming all request messages

- ***-E*** : (optional) enable state aware mode

- ***-R*** : (optional) enable region-level mutation operators

- ***-F*** : (optional) enable false negative reduction mode

- ***-c script*** : (optional) name or full path to a script for server cleanup

- ***-q algo***: (optional) state selection algorithm (e.g., 1. RANDOM_SELECTION, 2. ROUND_ROBIN, 3. FAVOR)

- ***-s algo***: (optional) seed selection algorithm (e.g., 1. RANDOM_SELECTION, 2. ROUND_ROBIN, 3. FAVOR)


Example command: 
```bash
gonet-fuzz -d -i in -o out -N <server info> -x <dictionary file> -P <protocol> -D 10000 -q 3 -s 3 -E -K -R <executable binary and its arguments (e.g., port number)>
```

# TBD
A pratical fuzzing with a protocol (RTSP) with details will be given.


# commit records:

# 6.2a

can't trim any more.
next step add byte analysis filter.

18-23 counts/min.(close to FFuzz. Due to the socket limitation, the fuzzing throughput is high enough).
Now focusing on egde coverage rate.


# 6.1a
trim the coding and ban the eagle

18-20 counts/min!

# 5.31a
temporary named it light fuzz

# 5.30a
latest showmap

# 5.28a
update gonet-showmap and Makefile

# 5.26a
update new makefile

# 5.25a
add showmap module and update NN module

# 4.07a
some modification
# 4.06a
update run_target，
Now trying to solve other structure. Socket communication

# 4.01a
Determine the route of implementation.
next step:
1. modify dry_run to meet network program and run_target corresponding to which.
2, gen_mutation

# 3.31a
Temporary keep the copy seeds and pivot testcases.
Now trying to build the whole structure and let it run up.

# 3.26a
add queue scheme(temporary not finished yet. read_testcases still need to debug and have a deep comprehension)

neuzz abandon the queue scheme of AFL. and Fuzzing directly based on IO. (simple but low efficiency!)

the original IO scheme is not efficient. Therefore I added read_testcases at this commit.

# 3.25a
refomat the the coding, should not effect the model.

# 3.24a
fix up the Version Error


# 3.21a
Some meaningless judgments and ifdefine affect the readability of the code

The current experimental mode attempts to refactor code to streamline

currently modified to dry_run


# 3.13a
Removed all code from previous gofuzz,
The current new code uses AFLNet as the bottom layer
