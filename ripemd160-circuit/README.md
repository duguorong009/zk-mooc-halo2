## RIPEMD160 Circuit(Halo2-ce)
  * ZKP/WEB3 Hackthon Project  
  * zk-Circuits Track - Category 4 (Circuit development in Halo2-ce)


### Description
 The goal of project is to implement and improve the ZK circuit of RIPEMD160 hashing function using [Halo2-ce](https://github.com/halo2-ce/halo2) library.  

### Techniques
 The project needs the skills of cryptographic research, ZK circuit development, Halo2-ce library, and Rustlang.

### How I approached the problem
  - Read the cryptography [paper](https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf) of RIPEMD160-hash function
  - Implement the native version of hash function 
  - Develop the ZK circuit using Halo2-ce
  - Improve the circuit

### NOTES
The repo has 2 branches - `main` and `origin-ripemd-160`.  
The `main` branch includes the optimized circuit`(4 advice cols + 3 table(fixed) cols + 18 selectors)`,   
while the `origin-ripemd-160` includes the less optimized one`(6 advice cols + 3 table(fixed) cols + 18 selectors)`.  
The `origin-ripemd-160` branch circuit is better for understanding, and it is a good starting point of benchmarking.   
  
Following table shows the benchmarking comparison between 2 circuit versions.(Device: Dell G15 5520 laptop ([spec](https://www.dell.com/support/manuals/en-us/g-series-15-5520-laptop/dell-g15-5520-setup-and-specifications/processor?guid=guid-5487570d-81b8-4be9-8a7a-38ee06c4b03d&lang=en-us)))    
```
                  Setup generation | Proof generation  | Proof verification
original              41.7325 s    |     89.1702 s     |     32.5339 ms    
optimized(main)       40.7184 s    |     82.1124 s     |     33.0337 ms
```
After reducing the number of columns, we can see the significant improvement in proof generation time.  
The benchmarking code(provided from [Scroll](https://scroll.io/)) can be found in `benchmarking` dir of this repo.

### How to run tests & benchmark
- Test
```
git clone git@github.com:duguorong009/zk-mooc-halo2.git
cd zk-mooc-halo2/ripemd160-circuit/
cargo test
```

- Benchmarking
```
git clone git@github.com:duguorong009/zk-mooc-halo2.git
cd zk-mooc-halo2/benchmarking/
DEGREE=17 cargo test -- --nocapture
```

