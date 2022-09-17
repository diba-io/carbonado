# Carbonado

> An apocalypse-resistant data storage format for the truly paranoid.

Designed to keep encrypted, durable, compressed, provably replicated consensus-critical data, without need for a blockchain or powerful hardware. Decoding and encoding can be done in the browser through WebAssembly, built into remote nodes on P2P networks, kept on S3-compatible cloud storage, or locally on-disk as a single highly portable flat file container format.

## Features

Carbonado has features to make it resistant against:

- Drive failure and Data loss
    - Uses [bao encoding](https://github.com/oconnor663/bao) so it can be uploaded to a remote peer, and random 1KB slices of that data can be periodically checked against a local hash to verify data replication and integrity. This way, copies can be distributed geographically; in case of a coronal mass ejection or solar flare, at most, only half the planet will be affected.
- Surveillance
    - Files are encrypted at-rest by default using [ecies authenticated encryption](https://docs.rs/ecies/latest/ecies/) from secp256k1 keys, which can either be provided or derived from a mnemonic.
- Theft
    - Decoding is done by the client with their own keys, so it won't matter if devices where data is stored are taken or lost, even if the storage media is unencrypted.
- Digital obsolescence
    - All project code, dependencies, and programs will be vendored into a tarball and made available in Carbonado format with every release.
- Bit rot and cosmic rays
  - As a final encoding step, forward error correction codes are added using [zfec](https://github.com/thornleywalker/zfec-rs), to augment the ones already used in some filesystems and storage media.

All without needing a blockchain, however, they can be useful for periodically checkpointing data in a durable place.

### Checkpoints

Carbonado supports an optional Bitcoin-compatible HD wallet with a specific derivation path that can be used to secure timestamped Carbonado Checkpoints using an on-chain OP_RETURN.

Checkpoints are structured human-readable yaml files that can be used to reference other carbonado-encoded files. They can also include an index of all the places the file has been stored, so multiple locations on the internet that can be checked for the presence of Carbonado-encoded data for that hash.

## Applications

### Contracts

RGB contract consignments must be encoded in a consensus-critical manner that is also resistant to data loss, otherwise, they cannot be imported or spent.

### Content

Includes metadata for mime type and preview content, good for NFTs and UDAs, especially for taking full possession and self-hosting data, or paying peers to keep it safe, remotely.

### Code

Code, dependencies, and programs can be vendored and preserved wherever they are needed. This helps ensure data is accessible, even if there's no longer internet access, or package managers are offline.

## Comparisons

### Ethereum

On Ethereum, all contract code is replicated by nodes for all addresses at all times. This results in scalability problems, is prohibitively expensive for larger amounts of data, and exposes all data for all contract users, in addition to the possibility it can be altered for all users without their involvement at any time.

Carbonado is specifically designed for encoding RGB contracts, which are to be kept off-chain, encrypted, and safe.

### IPFS

IPFS stores data into a database called BadgerDS, encoded in IPLD formats, which isn't the same as a simple, portable flat file format that can be transferred and stored out-of-band of any server, service, or node.

### Filecoin

Carbonado uses Bao stream verification based on the performant [Blake3 hash algorithm](https://github.com/BLAKE3-team/BLAKE3), to establish a statistical proof of replication (which can be proven repeatedly over time). Filecoin instead uses zk-SNARKs, which are notoriously computationally expensive, often recommending GPU acceleration. In addition, Filecoin requires a blockchain, whereas Carbonado does not.

### Storm

Storm is great, but it has a file size limit of 16MB, and while files can be split into chunks, they're stored directly in an embedded database, and not in flat files. Ideally, Carbonado would be used in conjunction with Storm.
