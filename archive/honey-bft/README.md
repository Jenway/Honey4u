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

### Honey::Core

HB BFT is based on Asyncronus Common Subset

HB BFT consist of two part: broadcast and aggrement

Dumbo , similiary, but using PRBC + MVBA

It basically only depends on Honey::Crypto

And also `std::coroutine`
