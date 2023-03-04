# Carbonado

> An apocalypse-resistant data storage format for the truly paranoid.

Carbonado is an archival format for encrypted, durable, compressed, provably replicated consensus-critical data, without need for a blockchain or powerful hardware. Decoding and encoding can be done in the browser through WebAssembly, built into remote nodes on P2P networks, kept on S3-compatible cloud storage, or locally on-disk as a single highly portable flat file container format.

[![Build status](https://img.shields.io/github/actions/workflow/status/diba-io/carbonado/rust.yaml?branch=main&style=flat-square)](https://github.com/diba-io/carbonado/actions/workflows/rust.yaml)
[![Crates.io](https://img.shields.io/crates/v/carbonado?style=flat-square)](https://docs.rs/carbonado/latest/carbonado/)
[![docs.rs](https://img.shields.io/docsrs/carbonado?label=docs&style=flat-square)](https://docs.rs/carbonado/latest/carbonado/)
[![License: MIT](https://img.shields.io/crates/l/carbonado?style=flat-square)](https://mit-license.org)
[![Telegram](https://img.shields.io/badge/telegram-invite-blue?style=flat-square)](https://t.me/+eQk5aQ5--iUxYzVk)

## Features

The Carbonado archival format has features to make it resistant against:

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

### Documentation

More detailed information on formats and operations can be found in the [carbonado crate docs](https://docs.rs/carbonado/latest/carbonado), hosted on [docs.rs](https://docs.rs).

There will also be a list of specs, known as [CHIPs](https://github.com/diba-io/CHIPs).

### Ecosystem

Carbonado is a novel archival format around which tools are built in order to better utilize it. There will be several storage provider frontends with support planned for:

- [x] HTTP
- [ ] Storm
- [ ] Hypercore
- [ ] IPFS
- [ ] BitTorrent
- [ ] rsync
- [ ] SFTP
- [ ] S3-compatible object storage

Let us know if any of these particular use-cases interests you!

The [carbonado-node](https://github.com/diba-io/carbonado-node) is where these implementations are taking place. There is also work planned for [carbonado-clients](https://github.com/diba-io/carbonado-clients).

### Checkpoints

Carbonado storage clients support the use of an optional Bitcoin-compatible HD wallet with a specific derivation path that can be used to secure timestamped Carbonado Checkpoints using an on-chain OP_RETURN.

Checkpoints are structured human-readable YAML files that can be used to reference other Carbonado-encoded files. They can also include an index of all the places the file has been stored, so multiple locations on the internet that can be checked for the presence of Carbonado-encoded data for that hash, in addition to other metadata needed to retrieve, decode, and serve across storage provider frontends.

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

Carbonado was was designed for encoding data for digital assets of arbitrary length, which is to be kept off-chain, encrypted, and safe.

### IPFS

IPFS stores data into a database called BadgerDS, encoded in IPLD formats, which isn't the same as a simple, portable flat file format that can be transferred and stored out-of-band of any server, service, or node. If the storage backend is swapped out, IPFS is a perfectly fine way to transfer data across a P2P network. Carbonado will support an IPFS frontend.

### Filecoin

Carbonado uses Bao stream verification based on the performant [Blake3 hash algorithm](https://github.com/BLAKE3-team/BLAKE3), to establish a statistical proof of replication (which can be proven repeatedly over time). Filecoin instead uses zk-SNARKs, which are notoriously computationally expensive, often recommending GPU acceleration. In addition, Filecoin requires a blockchain, whereas Carbonado does not. Carbonado is a direct alternative to Filecoin, and so no compatibility is needed.

### Storm

Storm is great, but it has a file size limit of 16MB, and while files can be split into chunks, they're stored directly in an embedded database, and not in flat files. Carbonado will support a Storm frontend.

## Error correction

Some decisions were made in how error correction is handled. A chunking forward error correction algorithm was used, called Zfec, which is used in [Tahoe-LAFS](https://tahoe-lafs.org/trac/tahoe-lafs). Similar to how RAID 5 and 6 stripes parity bits across a storage array, Zfec encodes bits in such a manner where only k valid of m total chunks are needed to reconstruct the original. This becomes more complicated by the fact that Zfec does not have integrity checks built-in. Bao is used to verify the integrity of the decoded input; if the integrity check fails, we can't be quite sure which chunk failed. So, there are two ways to handle this; either create a hash for each chunk and persist it in a safe place out-of-band, or, try each combination of chunks until a combination is found that works. The latter approach is used here, since the need for scrubbing should hopefully be a relatively rare occurrence, especially if reliable storage media is used, a CoW filesystem set to scrub for bitrot, or there's an entire copy that's good. However, if you're down to your last copy, and all you have is the hash (name of the file) and some good chunks, the scrub method in this crate should help, even if it can be computationally-intensive.

Running scrub on an input that has no errors in it actually returns an error; this is to prevent the need for unnecessary writes of bytes that don't need to be scrubbed. This is useful in append-only datastores and metered cloud storage scenarios.

The values 4/8 were chosen for Zfec's k of m parameters, meaning, only 4 valid chunks are needed, but 8 chunks are provided. Half of the chunks could fail to decode. This doubles the size of the data, on top of the encryption and integrity-checking, but such is the price of paranoia. Also, a non-prime k is needed to align chunk size with Bao slice size.

Bao only supports a fixed chunk size of 1KB, so the smallest a Carbonado file can be is 8KB. This also aligns well with 4KB HDD sectors, for less wasted space.

Storage providers will not need to use RAID to protect storage volumes so long as `carbonadod` is configured to store archive chunks on 8 separate storage volumes. In case a volume fails, scrubbing will recover the missing data. When data is served, only 4 of the chunks are needed. This results in a sort of user-level "application RAID", which is inline with Carbonado's design principles of being a flexible format with user-friendly configuration options. It's designed to be as approachable for "Uncle Jim" hobbyists to use as it is for professional mining datacenters bagged in FIL or XCH.

## Terminology

Files are split into segments of a maximum of 1MB input length. This was chosen because it aligns well with the IPFS IPLD, Storm, and BitTorrent frontends. These segments are tracked and combined separately using catalog files, which may also store additional metadata about the files needed for specific storage frontends. Chunks are used for error correction, and can be stored separately on separate volumes. Slices are relevant to stream verification, are hardcoded to be 1KB in size, and are also a reference to Rust byte slices (references to an array of unsighted 8-bit integers).

In summary: File of n MB -> n MB / 1MB Catalog Segments -> 8x Zfec Chunks -> >=1MB / 8x / 1024 Byte Slices

Only chunks are stored separately on-disk. Slices are referenced in-memory, and how segments are streamed is frontend-specific. Segmentation also helps with computational parallelization, reduces node memory requirements, and helps spread IO load across storage volumes.
