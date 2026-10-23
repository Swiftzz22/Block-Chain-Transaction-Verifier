# Blockchain Transaction Verifier (POSIX C)

A multi-process blockchain transaction verifier written in C for my Operating Systems course at BITS Pilani, Goa.

## What it does
- Reads the IPC keys from an input file and attaches to a **System V shared-memory segment** and **message queue** shared with a helper process.
- For each block: receives the helper's message, **decrypts wallet IDs**, validates transactions, flags suspicious ones, and sums the value of valid transactions.
- Tracks wallets with a hand-written **chained hash map** and per-wallet **adjacency lists** for transaction relationships.
- Checks proof-of-work style difficulty by counting leading zeros of a computed hash.
- Frees every allocation explicitly (hash map and adjacency-list cleanup) so the program runs leak-free.

## Concepts
Inter-process communication (`shmget`/`shmat`, `msgget`/`msgsnd`/`msgrcv`), message-protocol design between processes, manual memory management, hash tables, graph representation.

## Build & run
```bash
gcc -O2 -o verifier solution.c
./verifier <input-file>
```
*(The helper process and test inputs were provided by the course and are not included.)*

## What I learned
Most bugs were protocol mismatches between processes, not logic errors. Getting the message format and shared-memory layout to agree exactly, and debugging across process boundaries, taught me to treat interfaces between components as the riskiest part of a system.
