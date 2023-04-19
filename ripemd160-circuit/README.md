## RIPEMD160 Circuit(Halo2)
  * ZKP/WEB3 Hackthon Project  
  * zk-Circuits Track - Category 4 (Circuit development in Halo2-ce)


### Description
 The goal of project is to implement and improve the ZK circuit of RIPEMD160 hashing function using [Halo2-ce](https://github.com/halo2-ce/halo2).  
 This repo includes the implementation of RIPEMD160 hashing circuit.


### Techniques
 The project needs the skills of ZKP circuit research and development, Halo2-ce library, and Rustlang.


### How I approached the problem
  - Read the cryptography paper of RIPEMD160-hash function
  - Implement the function myself
  - Develop the ZK circuit using Halo2-ce
  - Improve the circuit

### NOTES
The repo has 2 branches - `main` and `origin-ripemd-160`.  
`main` branch includes the optimized circuit(4 advice cols + 3 table(fixed) cols + 18 selectors), while  
`origin-ripemd-160` includes the less optimized one(6 advice cols + 3 table(fixed) cols + 18 selectors).  
`origin-ripemd-160` branch circuit is better for understanding, and it is a good starting point of benchmarking.   
  
Following table shows the benchmarking comparison between 2 circuit versions.  
```
                  Setup generation | Proof generation  | Proof verification
original              40.9272 s    |     89.2146 s     |     34.6084 ms    
optimized(main)       41.1502 s    |     83.3291 s     |     34.6834 ms
```
After decreasing the number of columns, it is clear that there is improvement in proof generation time.
The benchmarking code can be found in `benchmarking` dir of this repo.
