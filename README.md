# GONet

GONet is a Gradient-Oriented graybox fuzzing tool for stateful network protocols.

Before Fuzzing, We highly recommend you to read [Neuzz](https://github.com/Dongdongshe/neuzz) and [AFLNet](https://github.com/aflnet/aflnet) to know some basic concepts about fuzzing especially for stateful network.


## Prerequisites

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 lib32z1

# Install clang (as required by GONet to enable llvm_mode)
sudo apt-get install clang
# Install graphviz development
sudo apt-get install graphviz-dev libcap-dev


```
### Python Environment:
- Python 2.7
- Tensorflow
- Keras

We recommend to use conda virtual env to avoid the python version shift problem.


## Before Start
Set CPU scaling algorithm and core dump notification with **root**.

```
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
echo core >/proc/sys/kernel/core_pattern
```

## Build GONet


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
export GONet=$(pwd)/GOFuzz
export WORKDIR=$(pwd)
export PATH=$PATH:$GONet
export AFL_PATH=$GONet
```

## Usage

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

## Applying GONet in live555

A pratical example in fuzzing with a protocol (RTSP).

### Build Live555
```bash
cd $WORKDIR
# Clone live555 repository
git clone https://github.com/rgaufman/live555.git
# Move to the folder
cd live555
# Checkout the buggy version of Live555
git checkout ceeb4f4
# Apply a patch. See the detailed explanation for the patch below
patch -p1 < $GONet/tutorials/live555/ceeb4f4_states_decomposed.patch
# Generate Makefile
./genMakefiles linux
# Compile the source
make clean all
```

### Test Live555
```bash
# test live555 to make sure everything is ok.
cd $WORKDIR/live555/testProgs
./testOnDemandRTSPServer 8554

# Crtl+C (exit).
```

### Generate the Gradient File. 
```bash
# Copy the showmap file and NN Server to target program DIR.
cd $GONet
cp ./gonet-showmap ./gonet-nnserver.py $WORKDIR/live555/testProgs/
cp -r ./Materials/live555/queue ./Materials/live555/replayable-queue $WORKDIR/live555/testProgs/

# Start Training (may take hours.)
cd $WORKDIR/live555/testProgs
python gonet-nnserver.py ./testOnDemandRTSPServer 8554
```

### Fuzzing
```bash
# Make sure in the right DIR
cd $WORKDIR/live555/testProgs
# Start Fuzz
light-fuzz -d -i $GONet/tutorials/live555/in-rtsp -o out-live555 -N tcp://127.0.0.1/8554 -x $GONet/tutorials/live555/rtsp.dict -P RTSP -D 10000 -q 3 -s 3 -E -K -R ./testOnDemandRTSPServer 8554
```


## TBD



## commit records:

### 6.9a
Update:
1. gonet-showmap DIR config
2. gonet-nnserver DIR 
3. light-server
4. README 
5. Makefile

### 6.8a
That is, add gradient module on light-fuzz 
and finish the Debugging of light-fuzz.

next steps:
modify the file diretory.

### 6.7b
change the mutation method of light-fuzz.
remove all original mutation methods.
identify the start byte and the end byte of queueing.

### 6.6b
remove the deterministic mutations of light fuzz.
next step directly parse gradient file and mutate everything.


### 6.6a
update gonnet-nnserver 
fix the bugs of gonnet-showmap: (exits with code 1 when the testcase timeout).

### 6.4a
update gonet-nnserver

### 6.2a

can't trim any more.
next step add byte analysis filter.

18-23 counts/min.(close to FFuzz. Due to the socket limitation, the fuzzing throughput is high enough).
Now focusing on egde coverage rate.


### 6.1a
trim the coding and ban the eagle

18-20 counts/min!

### 5.31a
temporary named it light fuzz

### 5.30a
latest showmap

### 5.28a
update gonet-showmap and Makefile

### 5.26a
update new makefile

### 5.25a
add showmap module and update NN module

### 4.07a
some modification
### 4.06a
update run_target，
Now trying to solve other structure. Socket communication

### 4.01a
Determine the route of implementation.
next step:
1. modify dry_run to meet network program and run_target corresponding to which.
2. gen_mutation

### 3.31a
Temporary keep the copy seeds and pivot testcases.
Now trying to build the whole structure and let it run up.

### 3.26a
add queue scheme(temporary not finished yet. read_testcases still need to debug and have a deep comprehension)

neuzz abandon the queue scheme of AFL. and Fuzzing directly based on IO. (simple but low efficiency!)

the original IO scheme is not efficient. Therefore I added read_testcases at this commit.

### 3.25a
refomat the the coding, should not effect the model.

### 3.24a
fix up the Version Error


### 3.21a
Some meaningless judgments and ifdefine affect the readability of the code

The current experimental mode attempts to refactor code to streamline

currently modified to dry_run


### 3.13a
Removed all code from previous gofuzz,
The current new code uses AFLNet as the bottom layer
