# Running Benchmarks
This document explains how to benchmark the codebase and read benchmarks' results. It also provides a step-by-step tutorial to run benchmarks on [Amazon Web Services (AWS)](https://aws.amazon.com) accross multiple data centers (WAN).

## Local Benchmarks
When running benchmarks, the codebase is automatically compiled with the feature flag `benchmark`. This enables the node to print some special log entries that are then read by the python scripts and used to compute performance. These special log entries are clearly indicated with comments in the code: make sure to not alter them (otherwise the benchmark scripts will fail to interpret the logs).

### Parametrize the benchmark
After cloning the repo and [installing all dependencies](https://github.com/akhilsb/pqsmr-rs#quick-start), you can use [Fabric](http://www.fabfile.org/) to run benchmarks on your local machine.  Locate the task called `local` in the file [fabfile.py](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark/fabfile.py):
```python
@task
def local(ctx):
    ...
```
The task specifies two types of parameters, the *benchmark parameters* and the *nodes parameters*. The benchmark parameters look as follows:
```python
bench_params = {
    'nodes': 4,
    'workers': 1,
    'rate': 50_000,
    'tx_size': 512,
    'faults': 0,
    'duration': 20,
}
```
They specify the number of primaries (`nodes`) and workers per primary (`workers`) to deploy, the input rate (tx/s) at which the clients submits transactions to the system (`rate`), the size of each transaction in bytes (`tx_size`), the number of faulty nodes ('faults), and the duration of the benchmark in seconds (`duration`). The minimum transaction size is 9 bytes, this ensure that the transactions of a client are all different. The benchmarking script will deploy as many clients as workers and divide the input rate equally amongst each client. For instance, if you configure the testbed with 4 nodes, 1 worker per node, and an input rate of 1,000 tx/s (as in the example above), the scripts will deploy 4 clients each submitting transactions to one node at a rate of 250 tx/s. When the parameters `faults` is set to `f > 0`, the last `f` nodes and clients are not booted; the system will thus run with `n-f` nodes (and `n-f` clients). 

The nodes parameters determine the configuration for the primaries and workers:
```python
node_params = {
    'header_size': 1_000,
    'max_header_delay': 100,
    'gc_depth': 50,
    'sync_retry_delay': 10_000,
    'sync_retry_nodes': 3,
    'batch_size': 500_000,
    'max_batch_delay': 100
}
```
They are defined as follows:
* `header_size`: The preferred header size. The primary creates a new header when it has enough parents and enough batches' digests to reach `header_size`. Denominated in bytes.
* `max_header_delay`: The maximum delay that the primary waits between generating two headers, even if the header did not reach `max_header_size`. Denominated in ms.
* `gc_depth`: The depth of the garbage collection (Denominated in number of rounds).
* `sync_retry_delay`: The delay after which the synchronizer retries to send sync requests. Denominated in ms.
* `sync_retry_nodes`: Determine with how many nodes to sync when re-trying to send sync-request. These nodes are picked at random from the committee.
* `batch_size`: The preferred batch size. The workers seal a batch of transactions when it reaches this size. Denominated in bytes.
* `max_batch_delay`: The delay after which the workers seal a batch of transactions, even if `max_batch_size` is not reached. Denominated in ms.

### Configuring HashRand
Extract the files from `hashrand-config` directory into the `benchmark` directory. For example, if running a protocol on $n=4$ nodes, extract files from `hrnd-4.zip` file into this folder. If `PQ-Tusk` needs to be instantiated with BLS signatures, extract the files in the `tkeys-{n}.tar.gz` file into this directory. Further, change the `consensus/src/lib.rs` file from lines 139-145 and configure the `hashrand` common coin provider to instead use `Dfinity-DVRF` beacon.

In case custom configuration files for a different number of nodes need to be generated, check out the [HashRand](https://github.com/akhilsb/hashrand-rs) repository. 

### Run the benchmark
Once you specified both `bench_params` and `node_params` as desired, run:
```
$ fab local
```
This command first recompiles your code in `release` mode (and with the `benchmark` feature flag activated), thus ensuring you always benchmark the latest version of your code. This may take a long time the first time you run it. It then generates the configuration files and keys for each node, and runs the benchmarks with the specified parameters. It finally parses the logs and displays a summary of the execution similarly to the one below. All the configuration and key files are hidden JSON files; i.e., their name starts with a dot (`.`), such as `.committee.json`.
```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Faults: 0 node(s)
 Committee size: 4 node(s)
 Worker(s) per node: 1 worker(s)
 Collocate primary and workers: True
 Input rate: 50,000 tx/s
 Transaction size: 512 B
 Execution time: 19 s

 Header size: 1,000 B
 Max header delay: 100 ms
 GC depth: 50 round(s)
 Sync retry delay: 10,000 ms
 Sync retry nodes: 3 node(s)
 batch size: 500,000 B
 Max batch delay: 100 ms

 + RESULTS:
 Consensus TPS: 46,478 tx/s
 Consensus BPS: 23,796,531 B/s
 Consensus latency: 464 ms

 End-to-end TPS: 46,149 tx/s
 End-to-end BPS: 23,628,541 B/s
 End-to-end latency: 557 ms
-----------------------------------------
```
The 'Consensus TPS' and 'Consensus latency' respectively report the average throughput and latency without considering the client. The consensus latency thus refers to the time elapsed between the block's creation and its commit. In contrast, 'End-to-end TPS' and 'End-to-end latency' report the performance of the whole system, starting from when the client submits the transaction. The end-to-end latency is often called 'client-perceived latency'. To accurately measure this value without degrading performance, the client periodically submits 'sample' transactions that are tracked across all the modules until they get committed into a block; the benchmark scripts use sample transactions to estimate the end-to-end latency.

## AWS Benchmarks
This repo integrates various python scripts to deploy and benchmark the codebase on [Amazon Web Services (AWS)](https://aws.amazon.com). They are particularly useful to run benchmarks in the WAN, across multiple data centers. This section provides a step-by-step tutorial explaining how to use them.

### Step 1. Set up your AWS credentials
Set up your AWS credentials to enable programmatic access to your account from your local machine. These credentials will authorize your machine to create, delete, and edit instances on your AWS account programmatically. First of all, [find your 'access key id' and 'secret access key'](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-creds). Then, create a file `~/.aws/credentials` with the following content:
```
[default]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
```
Do not specify any AWS region in that file as the python scripts will allow you to handle multiple regions programmatically.

### Step 2. Add your SSH public key to your AWS account
You must now [add your SSH public key to your AWS account](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html). This operation is manual (AWS exposes little APIs to manipulate keys) and needs to be repeated for each AWS region that you plan to use. Upon importing your key, AWS requires you to choose a 'name' for your key; ensure you set the same name on all AWS regions. This SSH key will be used by the python scripts to execute commands and upload/download files to your AWS instances.
If you don't have an SSH key, you can create one using [ssh-keygen](https://www.ssh.com/ssh/keygen/):
```
$ ssh-keygen -f ~/.ssh/aws
```

### Step 3. Configure the testbed
The file [settings.json](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark/settings.json) (located in [pqsmr-rs/benchmarks](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark)) contains all the configuration parameters of the testbed to deploy. Its content looks as follows:
```json
{
    "key": {
        "name": "aws",
        "path": "/home/akhil/.ssh/aws"
    },
    "port": 5000,
    "hrnd_port": 8500,
    "client_base_port": 7000,
    "client_run_port": 9000,
    "repo": {
        "name": "pqsmr-rs",
        "url": "https://github.com/akhilsb/pqsmr-rs",
        "branch": "master"
    },
    "instances": {
        "type": "c5.large",
        "regions": ["us-east-1","us-east-2","us-west-1","us-west-2","ca-central-1", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]
    }
}
```
The first block (`key`) contains information regarding your SSH key:
```json
"key": {
    "name": "aws",
    "path": "/absolute/key/path"
},
```
Enter the name of your SSH key; this is the name you specified in the AWS web console in step 2. Also, enter the absolute path of your SSH private key (using a relative path won't work). 


The second block (`ports`) specifies the TCP ports to use:
```json
"port": 5000,
```
PQ-Tusk requires a number of TCP ports, depening on the number of workers per node, Each primary requires 2 ports (one to receive messages from other primaties and one to receive messages from its workers), and each worker requires 3 ports (one to receive client transactions, one to receive messages from its primary, and one to receive messages from other workers). Note that the script will open a large port range (5000-7000) to the WAN on all your AWS instances. 

The third block (`repo`) contains the information regarding the repository's name, the URL of the repo, and the branch containing the code to deploy: 
```json
"repo": {
        "name": "pqsmr-rs",
        "url": "https://github.com/akhilsb/pqsmr-rs",
        "branch": "master"
    },
```
Remember to update the `url` field to the name of your repo. Modifying the branch name is particularly useful when testing new functionalities without having to checkout the code locally. 

The the last block (`instances`) specifies the [AWS instance type](https://aws.amazon.com/ec2/instance-types) and the [AWS regions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions) to use:
```json
"instances": {
    "type": "c5.large",
    "regions": ["us-east-1","us-east-2","us-west-1","us-west-2","ca-central-1", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]
}
```
The instance type selects the hardware on which to deploy the testbed. For example, `m5d.8xlarge` instances come with 32 vCPUs (16 physical cores), 128 GB of RAM, and guarantee 10 Gbps of bandwidth. The python scripts will configure each instance with 300 GB of SSD hard drive. The `regions` field specifies the data centers to use. If you require more nodes than data centers, the python scripts will distribute the nodes as equally as possible amongst the data centers. All machines run a fresh install of Ubuntu Server 20.04.

### Step 4. Create a testbed
The AWS instances are orchestrated with [Fabric](http://www.fabfile.org) from the file [fabfile.py](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark/fabfile.pyy) (located in [pqsmr-rs/benchmarks](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark)); you can list all possible commands as follows:
```
$ cd pqsmr-rs/benchmark
$ fab --list
```
The command `fab create` creates new AWS instances; open [fabfile.py](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark/fabfile.py) and locate the `create` task:
```python
@task
def create(ctx, nodes=2):
    ...
```
The parameter `nodes` determines how many instances to create in *each* AWS region. That is, if you specified 5 AWS regions as in the example of step 3, setting `nodes=2` will creates a total of 10 machines:
```
$ fab create

Creating 10 instances |██████████████████████████████| 100.0% 
Waiting for all instances to boot...
Successfully created 10 new instances
```
You can then clone the repo and install rust on the remote instances with `fab install`:
```
$ fab install

Installing rust and cloning the repo...
Initialized testbed of 10 nodes
```
This may take a long time as the command will first update all instances.
The commands `fab stop` and `fab start` respectively stop and start the testbed without destroying it (it is good practice to stop the testbed when not in use as AWS can be quite expensive); and `fab destroy` terminates all instances and destroys the testbed. Note that, depending on the instance types, AWS instances may take up to several minutes to fully start or stop. The command `fab info` displays a nice summary of all available machines and information to manually connect to them (for debug).

### Step 5. Run a benchmark
After setting up the testbed, running a benchmark on AWS is similar to running it locally (see [Run Local Benchmarks](https://github.com/akhilsb/pqsmr-rs/tree/master/benchmark#local-benchmarks)). Locate the task `remote` in [fabfile.py](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark/fabfile.py):
```python
@task
def remote(ctx):
    ...
```
The benchmark parameters are similar to [local benchmarks](https://github.com/akhilsb/pqsmr-rs/tree/master/benchmark#local-benchmarks) but allow to specify the number of nodes and the input rate as arrays to automate multiple benchmarks with a single command. The parameter `runs` specifies the number of times to repeat each benchmark (to later compute the average and stdev of the results), and the parameter `collocate` specifies whether to collocate all the node's workers and the primary on the same machine. If `collocate` is set to `False`, the script will run one node per data center (AWS region), with its primary and each of its worker running on a dedicated instance.
```python
bench_params = {
    'nodes': [10, 20, 30],
    'workers: 2,
    'collocate': True,
    'rate': [20_000, 30_000, 40_000],
    'tx_size': 512,
    'faults': 0,
    'duration': 300,
    'runs': 2,
}
```
Similarly to local benchmarks, the scripts will deploy as many clients as workers and divide the input rate equally amongst each client. Each client is colocated with a worker, and only submit transactions to the worker with whom they share the machine.

Once you specified both `bench_params` and `node_params` as desired, run:
```
$ fab remote
```
This command first updates all machines with the latest commit of the GitHub repo and branch specified in your file [settings.json](https://github.com/akhilsb/pqsmr-rs/blob/master/benchmark/settings.json) (step 3); this ensures that benchmarks are always run with the latest version of the code. It then generates and uploads the configuration files to each machine, runs the benchmarks with the specified parameters, and downloads the logs. It finally parses the logs and prints the results into a folder called `results` (which is automatically created if it doesn't already exists). You can run `fab remote` multiple times without fearing to override previous results, the command either appends new results to a file containing existing ones or prints them in separate files. If anything goes wrong during a benchmark, you can always stop it by running `fab kill`.
 
### Step 6. Plot the results
Once you have enough results, you can aggregate and plot them:
```
$ fab plot
```
This command creates a latency graph, a throughput graph, and a robustness graph in a folder called `plots` (which is automatically created if it doesn't already exists). You can adjust the plot parameters to filter which curves to add to the plot:
```python
plot_params = {
    'faults': [0],
    'nodes': [10, 20, 50],
    'workers': [1],
    'collocate': True,
    'tx_size': 512,
    'max_latency': [3_500, 4_500]
}
```

The first graph ('latency') plots the latency versus the throughput. It shows that the latency is low until a fairly neat threshold after which it drastically increases. Determining this threshold is crucial to understand the limits of the system. 

Another challenge is comparing apples-to-apples between different deployments of the system. The challenge here is again that latency and throughput are interdependent, as a result a throughput/number of nodes chart could be tricky to produce fairly. The way to do it is to define a maximum latency and measure the throughput at this point instead of simply pushing every system to its peak throughput (where latency is meaningless). The second graph ('tps') plots the maximum achievable throughput under a maximum latency for different numbers of nodes.

# Artifact Evaluation on Cloudlab/Custom testbeds
It is possible to evaluate our artifact on CloudLab/Chameleon. However, it would require us to change a few lines of code in the submitted artifact. The benchmarking code in the current artifact works in the following way.

1. It takes a user's AWS credentials and uses the AWS boto3 SDK to spawn AWS EC2 machines across the specified regions. 
2. It also establishes a network between them using the boto3 SDK. 
3. It gets the IP addresses of the spawned machines and installs the artifact in each machine using `tmux` and `SSH`. 
4. It then runs the artifact by executing a series of commands on the machines using `tmux` and `SSH`.

We describe the series of modifications to this structure to run benchmarks on Cloudlab/Chameleon. 

## Setting up the testbed
1. Running the benchmark on Cloudlab or Chameleon requires you to skip the first two steps and create machines manually. Therefore, instead of running `fab create` and `fab start` commands, create machines manually on Cloudlab/Chameleon, and establish a network between them. This network should enable processes on the machines to communicate with each other through `TCP`. 

## Installing the Artifact
2. The `hosts()` function in the file `benchmark/benchmark/instance.py` is responsible for configuring hosts in the network. We changed the function to the following for evaluation on custom testbeds. In case the code needs to be run on AWS, uncomment the commented part and comment the uncommented part of the `hosts` function. 
```
# To run on CloudLab/Chameleon, create a list of ip addresses and add them to a file titled 'instance_ips'.
def hosts(self, flat=False):
    import json
    with open("instance-ips.json") as json_file:
        json_data = json.load(json_file)
        if flat:
            return [x for y in json_data.values() for x in y]        
        else:
            return json_data
    #try:
    #    _, ips = self._get(['pending', 'running'])
    #    return [x for y in ips.values() for x in y] if flat else ips
    #except ClientError as e:
    #    raise BenchError('Failed to gather instances IPs', AWSError(e))
```
3. Then, create a file with the name `instance-ips.json` in the `benchmark/` directory. The file should have the following structure. The key of each item in the map should be the location where the nodes are located, and the value is an array of ip addresses in that region. The benchmark distributes processes evenly in machines across different regions. In case all nodes are located in one region, use one key to list all the ip addresses. **Note that the total number of ip addresses listed must be at least as much as the number of processes being run in the benchmark. To run multiple processes on a single machine, list the ip address multiple times in the array. For example, to run two processes on the machine with ip `10.43.0.231`, list it twice in the array as ["10.43.0.231","10.43.0.231",..].** To reproduce the results in the paper, we suggest giving each process 2 CPU cores and 4 GigaBytes of RAM. For example, if you have a machine with 8 cores and 16 GB of RAM, you can run four processes in it by listing its ip address four times in the array. 
```
{
    "Utah": ["10.43.0.231",”10.43.0.231”,"10.43.0.232","10.43.0.233"],
    "Wisconsin": ["10.43.0.234","10.43.0.235","10.43.0.236"]
}
```
4. Next, the code requires access to the machines on CloudLab/Chameleon. We used the `paramiko` authentication library in Python to remotely access the machines. 
You need to specify the required SSH key in the `settings.json` file in the `benchmark` folder. 
Further, the ports specified in the `settings.json` file should be open for communication in the spawned machines. 
Finally, the username in the file `remote.py` should be changed at 8 occurrences. We hardcoded the username `ubuntu` in the file `remote.py` (We apologize for this inconvenience). Change it to the appropriate username. (Leave it as is if the machines have Ubuntu OS). 
5. The configuration in `fabfile.py` needs to be changed to run the benchmark with the appropriate number of nodes. After this change, install the required dependencies to run the code in the `benchmark` folder. Pertinent instructions have been given in this file above. Then, run `fab install` to install the artifact in all the machines. Ensure that the machines have access to the internet to help access the dependencies necessary for installation. 
6. Finally, follow the instructions in the `benchmark/README.md` file from Step 4 (from installing the repo) to run the benchmarks and plot results. 

We note that the machines on Cloudlab and Chameleon do not mimic our geo-distributed testbed in AWS. This is because the AWS testbed has machines in 5 different continents, which implies a message delivery and round trip time between processes, and lower message bandwidth. As HashRand has a higher communication complexity compared to Dfinity-DVRF, we expect HashRand to have better numbers compared to Dfinity-DVRF on testbeds on Cloudlab and Chameleon. 

In case this procedure is too long/tedious, you can verify performance trends of HashRand by spawning a single big machine on Cloudlab/Chameleon and running a local benchmark with specified number of nodes.This would have a similar effect as spawning multiple smaller machines in a single datacenter. Running the benchmark in such a setup would also boost HashRand’s numbers because of higher communication bandwidth and lower round trip time. The computational efficiency of HashRand and its corresponding performance boost can be verified in this setting.