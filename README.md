# Post Quantum Asynchronous SMR
This repository implements a post-quantum secure asynchronous SMR protocol on top of Tusk. This protocol uses lattice-based <code>dilithium</code> signatures in place of <code>EdDSA</code> signatures used by Tusk. This protocol also uses <code>HashRand</code> ( https://github.com/akhilsb/hashrand-rs ) as a post-quantum secure random beacon protocol to achieve liveness in asynchrony. Please note that this repository is a research prototype that has **not** been rigorously tested for software bugs. Please use at your own risk. 

# PQ-Tusk
This repository has been cloned from [Narwhal](https://github.com/asonnino/narwhal).

This repo provides an implementation of PQ-Tusk. The codebase has been designed to be small, efficient, and easy to benchmark and modify. It has not been designed to run in production but uses real pq-cryptography ([dilithium](https://github.com/akhilsb/pqcrypto)), networking ([tokio](https://docs.rs/tokio)), and storage ([rocksdb](https://docs.rs/rocksdb)).

## Quick Start
The core protocols are written in Rust, but all benchmarking scripts are written in Python and run with [Fabric](http://www.fabfile.org/).
To deploy and benchmark a testbed of 4 nodes on your local machine, clone the repo and install the python dependencies:
```
$ git clone https://github.com/akhilsb/pqsmr-rs.git
$ cd pqsmr-rs/benchmark
$ pip install -r requirements.txt
```
You also need to install Clang (required by rocksdb) and [tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux) (which runs all nodes and clients in the background). 

### Configuring HashRand
HashRand requires configuration files of the form `nodes-{i}.json` and `ip_file` for configuring secure channels among nodes. A set of these configuration files are in the `benchmark/hashrand-config` directory for values $n=4,16,40,64$. Extract these files into the `benchmark` directory.  

Finally, run a local benchmark using fabric:
```
$ fab local
```
This command may take a long time the first time you run it (compiling rust code in `release` mode may be slow) and you can customize a number of benchmark parameters in `fabfile.py`. When the benchmark terminates, it displays a summary of the execution similarly to the one below.
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

## Next Steps
The next step is to read the paper [Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus](https://arxiv.org/pdf/2105.11827.pdf) and [HashRand: Efficient Asynchronous Random Beacon without Threshold Cryptographic Setup](https://eprint.iacr.org/2023/1755). An additional resource to better understand the Tusk consensus protocol is the paper [All You Need is DAG](https://arxiv.org/abs/2102.08325) as it describes a similar protocol. 

The README file of the [benchmark folder](https://github.com/akhilsb/pqsmr-rs/tree/master/benchmark) explains how to benchmark the codebase and read benchmarks' results. It also provides a step-by-step tutorial to run benchmarks on [Amazon Web Services (AWS)](https://aws.amazon.com) accross multiple data centers (WAN).

## License
This software is licensed as [Apache 2.0](LICENSE).
