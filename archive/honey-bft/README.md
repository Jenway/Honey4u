# Honey BFT

WIP

An implementation of:

- Honey Badger Byzantine Fault Tolerant (BFT) consensus algorithm
- Dumbo BFT
- And add a cache layer for them

## Build

```bash
cmake -B build && cmake --build build
```

It requires a compiler that support c++ std23

## Dependecies

### Honey::Crypto

The Honey Badger BFT relys on a bunch of Crypto utils,including:

Merkle Tree and Erasue coding

Threshold Encryption and Threshold Signature

ecdsa encryption (for dumbo) 

Therefor:

- openssl
- blst
- Intel ISA-L
- libSECP256K1

is needed

### Honey::Core

HB BFT is based on Asyncronus Common Subset

HB BFT consist of two part: broadcast and aggrement

Dumbo , similiary, but using PRBC + MVBA

It basically only depends on Honey::Crypto 

And also `std::coroutine`

### Honey::Execution

If designed properly, the Honey::Core wont rely on a specific Network library

Might trying implement a simple Netowork lib

Or we can simply using asio
