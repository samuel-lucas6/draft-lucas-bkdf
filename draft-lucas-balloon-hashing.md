---
title: "Balloon Hashing"
docname: draft-lucas-balloon-hashing-latest
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

venue:
  github: "samuel-lucas6/draft-lucas-balloon-hashing"
  latest: "https://samuel-lucas6.github.io/draft-lucas-balloon-hashing/draft-lucas-balloon-hashing.html"

author:
 -
    fullname: Samuel Lucas
    organization: Individual Contributor
    email: ietf.tree495@simplelogin.fr


normative:

  FIPS202:
    title: "FIPS PUB 202 - SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://doi.org/10.6028/NIST.FIPS.202
    author:
      -
        org: National Institute of Standards and Technology
    date: 2015

informative:

  PM99:
    title: "A Future-Adaptable Password Scheme"
    rc: "Proceedings of the 1999 USENIX Annual Technical Conference"
    target: https://www.usenix.org/legacy/publications/library/proceedings/usenix99/provos/provos.pdf
    author:
      -
        ins: N. Provos
        name: Niels Provos
        org: The OpenBSD Project
      -
        ins: D. Mazières
        name: David Mazières
        org: The OpenBSD Project
    date: 1999

  BCS16:
    title: "Balloon Hashing: A Memory-Hard Function Providing Provable Protection Against Sequential Attacks"
    rc: "Cryptology ePrint Archive, Paper 2016/027"
    target: https://eprint.iacr.org/2016/027
    author:
      -
        ins: D. Boneh
        name: Dan Boneh
        org: Stanford University
      -
        ins: H. Corrigan-Gibbs
        name: Henry Corrigan-Gibbs
        org: Stanford University
      -
        ins: S. Schechter
        name: Stuart Schechter
        org: Microsoft Research
    date: 2016

  RD16:
    title: "Proof of Space from Stacked Expanders"
    rc: "Theory of Cryptography. TCC 2016. Lecture Notes in Computer Science(), vol 9985, pp. 262–285"
    target: https://doi.org/10.1007/978-3-662-53641-4_11
    author:
      -
        ins: L. Ren
        name: Ling Ren
        org: Massachusetts Institute of Technology
      -
        ins: S. Devadas
        name: Srinivas Devadas
        org: Massachusetts Institute of Technology
    date: 2016

  AB16:
    title: "Efficiently Computing Data-Independent Memory-Hard Functions"
    rc: "Advances in Cryptology – CRYPTO 2016. CRYPTO 2016. Lecture Notes in Computer Science(), vol 9815, pp. 241–271"
    target: https://doi.org/10.1007/978-3-662-53008-5_9
    author:
      -
        ins: J. Alwen
        name: Joël Alwen
        org: IST Austria
      -
        ins: J. Blocki
        name: Jeremiah Blocki
        org: Microsoft Research
    date: 2016

  SP800-63B:
    title: "NIST SP 800-63B - Digital Identity Guidelines: Authentication and Lifecycle Management"
    target: https://doi.org/10.6028/NIST.SP.800-63b
    author:
      -
        ins: P. Grassi
        name: Paul Grassi
        org: NIST
      -
        ins: E. Newton
        name: Elaine Newton
        org: NIST
      -
        ins: J. Fenton
        name: James Fenton
        org: Altmode Networks
      -
        ins: R. Perlner
        name: Ray Perlner
        org: NIST
      -
        ins: A. Regenscheid
        name: Andrew Regenscheid
        org: NIST
      -
        ins: W. Burr
        name: William Burr
        org: Dakota Consulting
      -
        ins: J. Richer
        name: Justin Richer
        org: Bespoke Engineering
      -
        ins: N. Lefkovitz
        name: Naomi Lefkovitz
        org: NIST
      -
        ins: J. Danker
        name: Jamie Danker
        org: DHS
      -
        ins: Y. Choong
        name: Yee-Yin Choong
        org: NIST
      -
        ins: K. Greene
        name: Kristen Greene
        org: NIST
      -
        ins: M. Theofanos
        name: Mary Theofanos
        org: NIST
    date: 2017

  AB17:
    title: "Towards Practical Attacks on Argon2i and Balloon Hashing"
    rc: "2017 IEEE European Symposium on Security and Privacy (EuroS&P), Paris, France, 2017, pp. 142-157"
    target: https://doi.org/10.1109/EuroSP.2017.47
    author:
      -
        ins: J. Alwen
        name: Joël Alwen
        org: IST Austria
      -
        ins: J. Blocki
        name: Jeremiah Blocki
        org: Purdue University
    date: 2017

  ABP17:
    title: "Depth-Robust Graphs and Their Cumulative Memory Complexity"
    rc: "Advances in Cryptology – EUROCRYPT 2017. EUROCRYPT 2017. Lecture Notes in Computer Science(), vol 10212, pp. 3–32"
    target: https://doi.org/10.1007/978-3-319-56617-7_1
    author:
      -
        ins: J. Alwen
        name: Joël Alwen
        org: IST Austria
      -
        ins: J. Blocki
        name: Jeremiah Blocki
        org: Purdue University
      -
        ins: K. Pietrzak
        name: Krzysztof Pietrzak
        org: IST Austria
    date: 2017

  RD17:
    title: "Bandwidth Hard Functions for ASIC Resistance"
    rc: "Theory of Cryptography. TCC 2017. Lecture Notes in Computer Science(), vol 10677, pp. 466–492"
    target: https://doi.org/10.1007/978-3-319-70500-2_16
    author:
      -
        ins: L. Ren
        name: Ling Ren
        org: Massachusetts Institute of Technology
      -
        ins: S. Devadas
        name: Srinivas Devadas
        org: Massachusetts Institute of Technology
    date: 2017

  LGR21:
    title: "Partitioning Oracle Attacks"
    rc: "30th USENIX Security Symposium (USENIX Security 21), pp. 195–212"
    target: https://www.usenix.org/conference/usenixsecurity21/presentation/len
    author:
      -
        ins: J. Len
        name: Julia Len
        org: Cornell Tech
      -
        ins: P. Grubbs
        name: Paul Grubbs
        org: Cornell Tech
      -
        ins: T. Ristenpart
        name: Thomas Ristenpart
        org: Cornell Tech
    date: 2021

--- abstract

This document describes Balloon, a memory-hard function suitable for password hashing and password-based key derivation. It has proven memory-hardness properties, is built from any standard cryptographic hash function or extendable-output function (XOF), is resistant to cache-timing attacks, and is easy to implement whilst remaining performant.

--- middle

# Introduction

Balloon {{BCS16}} is a memory-hard password hashing and password-based key derivation function that was published shortly after the Password Hashing Competition (PHC), which recommended Argon2 {{?RFC9106}}. It is mentioned in a NIST Special Publication on authentication {{SP800-63B}} and has several advantages over prior password hashing algorithms:

- It has proven memory-hardness properties, making it resistant against sequential GPU/ASIC attacks. An adversary trying to save space pays a large penalty in computation time.
- It can be instantiated with any cryptographic hash function or XOF, making it a mode of operation for these existing algorithms.
- It uses a password-independent memory access pattern, making it resistant to cache-timing attacks. This property is especially relevant in cloud computing environments where multiple users can share the same physical machine.
- It is easy to implement whilst offering acceptable performance.

Unfortunately, the paper did not fully specify the algorithm nor provide guidance on parameters. Therefore, this document aims to rectify the situation based on existing interoperable implementations, real-world password hashing guidance, and research since the paper.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Throughout this document, "byte" refers to the same unit as "octet", namely an 8-bit sequence.

Operations:

- `x++`: incrementing the integer `x` by 1 after it has been used in a function.
- `a ^ b`: the bitwise XOR of `a` and `b`.
- `a % b`: the remainder when dividing `a` by `b`.
- `a || b`: the concatenation of `a` and `b`.
- `a[i]`: index 'i' of byte array/list 'a'.
- `a.Length`: the length of `a` in bytes.
- `a.Slice(i, l)`: the copy of `l` bytes from byte array `a`, starting at index `i`.
- `List(i, l)`: the creation of a new list containing `i` byte arrays, each with length `l`.
- `Hash(a)`: collision-resistant hashing of the byte array `a`.
- `BI(a)`: the conversion of byte array `a` into an unsigned, little-endian BigInteger.
- `INT32(x)`: the casting of BigInteger `x` into a signed 32-bit integer.
- `LE64(x)`: the little-endian encoding of unsigned 64-bit integer `x`.

Constants:

- `HASH_LEN`: the output length of the hash function in bytes. For an XOF, this is the minimum output length to obtain the maximum advertised security level. For example, a 256-bit output for an XOF targeting 128-bit security.
- `MIN_SPACECOST`: the minimum space cost, which is 1.
- `MIN_TIMECOST`: the minimum time cost, which is 1.
- `MIN_PARALLELISM`: the minimum parallelism, which is 1.
- `MIN_DELTA`: the minimum delta, which is 3.

# The Balloon Function

~~~
Balloon(password, salt, spaceCost, timeCost, delta)
~~~

The Balloon function can be divided into three steps:

1. Expand: a large buffer is filled with pseudorandom bytes derived by repeatedly hashing the password and salt. This buffer is divided into blocks the size of the hash function output length.
2. Mix: the buffer is mixed for the number of rounds specified by the user. Each block becomes equal to the hash of the previous block, the current block, and delta other blocks 'randomly' chosen from the buffer based on the salt.
3. Extract: the last block of the buffer is output as the password hash/derived key.

Inputs:

- `password`: the password to be hashed.
- `salt`: the unique salt.
- `spaceCost`: the memory size in blocks, which MUST be at least `MIN_SPACECOST`. A block is the size of the hash function output length in bytes.
- `timeCost`: the number of rounds, which MUST be at least `MIN_TIMECOST`.
- `delta`: the number of dependencies per block (a security parameter), which MUST be at least `MIN_DELTA`.

Outputs:

- The password hash/derived key the size of the hash function output length.

Steps:

~~~
buffer = List(spaceCost, HASH_LEN)
counter = 0

buffer[0] = Hash(LE64(counter++) || password || salt)
for m = 1 to spaceCost - 1
	buffer[m] = Hash(LE64(counter++) || buffer[m - 1])

for t = 0 to timeCost - 1
	for m = 0 to spaceCost - 1
		if m == 0
			previous = buffer[spaceCost - 1]
		else
			previous = buffer[m - 1]
		
		buffer[m] = Hash(LE64(counter++) || previous || buffer[m])

		for i = 0 to delta - 1
			idxBlock = Hash(LE64(t) || LE64(m) || LE64(i))
			idxBlock = Hash(LE64(counter++) || salt || idxBlock)
			other = BI(idxBlock) % spaceCost
			buffer[m] = Hash(LE64(counter++) || buffer[m] || buffer[INT32(other)])

return buffer[spaceCost - 1]
~~~

# The Balloon-M Function

~~~
BalloonM(password, salt, spaceCost, timeCost, parallelism, delta)
~~~

A limitation of Balloon is that it lacks parallelism because the value of each block depends on the value of the previous block. Balloon-M addresses this by invoking Balloon in parallel using multiple cores, XORing the outputs, and hashing the password, salt, and XORed output concatenated together. This provides greater memory hardness without increasing the delay.

Inputs:

- `password`: the password to be hashed.
- `salt`: the unique salt.
- `spaceCost`: the memory size in blocks, which MUST be at least `MIN_SPACECOST`. A block is the size of the hash function output length in bytes.
- `timeCost`: the number of rounds, which MUST be at least `MIN_TIMECOST`.
- `parallelism`: the number of CPU cores/Balloon calls in parallel, which MUST be at least `MIN_PARALLELISM`.
- `delta`: the number of dependencies per block (a security parameter), which MUST be at least `MIN_DELTA`.

Outputs:

- The password hash/derived key the size of the hash function output length.

Steps:

~~~
outputs = List(parallelism, HASH_LEN)

parallel for i = 0 to parallelism - 1
	newSalt = salt || LE64(i + 1)
	outputs[i] = Balloon(password, newSalt, spaceCost, timeCost, delta)

foreach output in outputs
	for i = 0 to output.Length - 1
		hash[i] = hash[i] ^ output[i]

return Hash(password || salt || hash)
~~~

# Implementation Considerations

In the context of a cryptographic library, it is RECOMMENDED to only provide users access to Balloon-M. Otherwise, users will be left wondering which variant to use and may incorrectly believe Balloon-M with `parallelism = 1` is equivalent to Balloon.

Implementations MAY hardcode `delta = MIN_DELTA` to avoid user confusion since other password hashing algorithms do not have this parameter. Moreover, the performance/security tradeoff is unclear from the paper.

Whilst the pseudocode uses a list of byte arrays for the buffer, slicing portions of a single large byte array to access/update blocks will likely be more performant.

Similarly, using a byte array counter instead of an integer that gets repeatedly converted to a byte array will likely aid performance.

With Balloon-M, the XORing of outputs can be skipped if `parallelism = 1`.

Finally, it is recommended to use an incremental hash function API rather than manually copying byte arrays to concatenate inputs as this is cleaner and may be more efficient.

# Choosing the Hash Function

The choice of cryptographic hash function/XOF affects the performance and security of Balloon in two ways:

1. For the same parameters, the attacker has an advantage if the algorithm is faster in hardware versus software. They will be able to do the computation in less time than the defender.
2. For the same delay, the defender will be forced to use smaller parameters with a slower cryptographic hash function/XOF in software. Using a faster algorithm in software means stronger parameters can be used.

It is RECOMMENDED to use a cryptographic hash function/XOF that is fast in software but relatively slow in hardware, such as BLAKE2b {{!RFC7693}}. As another example, SHA-512 is preferable to SHA-256 {{!RFC6234}}. Finally, SHA-3 {{FIPS202}} is NOT RECOMMENDED as it is slower in software compared to in hardware.

# Choosing the Parameters

The higher the `spaceCost`, `timeCost`, and `delta`, the longer it takes to compute an output. If these values are too small, security is unnecessarily reduced. If they are too large, there is a risk of user frustration and denial-of-service for different types of user devices and servers. To make matters even more complicated, these parameters may need to be increased over time as hardware gets faster.

The following procedure can be used to choose parameters:

1. If configurable in the implementation, set `delta` to 3. This value is used in the paper {{BCS16}}.
2. If using Balloon-M, set the `parallelism` to 1 on a server and 4 otherwise. This assumes most user devices have at least 4 CPU cores.
3. Establish the maximum acceptable delay for the user. For example, 100-500 ms for authentication, 250-1000 ms for file encryption, and 1000-5000 ms for disk encryption. On servers, you also need to factor in the maximum number of authentication attempts per second.
4. Determine the maximum amount of memory available, taking into account different types of user devices and denial-of-service. For instance, mobile phones versus laptops/desktops.
5. Convert the MiB/GiB memory size to bytes. Then set `spaceCost` to `bytes / HASH_LEN`, which is the number of blocks.
6. Find the `timeCost` that brings you closest to the maximum acceptable delay or target number of authentication attempts per second by running benchmarks.
7. If `timeCost` is only 1, reduce `spaceCost` to be able to increase `timeCost`. Performing multiple rounds is beneficial for security {{AB17}}.

Regrettably, Balloon has not yet been sufficiently investigated for generic parameter recommendations to be made. This is also difficult given how various cryptographic hash functions can be used.

In all cases, it is RECOMMENDED to use a 128- or 256-bit `salt`. Other `salt` lengths SHOULD NOT be used, and the `salt` length SHOULD NOT vary in your protocol/application. See the {{security-considerations}} section for guidance on generating the `salt`.

# Encoding Password Hashes

To store Balloon hashes in a database as strings, the following format SHOULD be used:

~~~
$balloon-hash$v=version$m=spaceCost,t=timeCost,p=parallelism$salt$hash
~~~

- `balloon-hash`: where `hash` is the proper, correctly punctuated name of the hash function in lowercase. For example, `sha-256`, not `sha256`. Another example is `sha3-256`, not `sha3256` or `sha-3-256`. Finally, `sha-512-256` for SHA-512 truncated to 256 bits, and `sha-512/256` for the SHA-512/256 algorithm.
- `v=version`: this is version 1 of Balloon. If the design is modified, the version will be incremented.
- `m=spaceCost`: the memory size in blocks, not KiB.
- `t=timeCost`: the number of rounds.
- `p=parallelism`: 0 if Balloon and 1+ for Balloon-M.
- `salt`: the salt encoded in Base64 with no padding {{!RFC4648}}.
- `hash`: the full/untruncated Balloon output encoded in Base64 with no padding {{!RFC4648}}.

Here is an example encoded hash:

~~~
$balloon-sha-256$v=1$m=1024,t=3,p=0$ZXhhbXBsZXNhbHQ$cWBD3/d3tEqnuI3LqxLAeKvs+snSicW1GVlnqmNEDfs
~~~

# Performing Key Derivation

As Balloon produces outputs the size of the hash function output length, there is a limit on the size of derived keys. To derive larger/multiple keys, the output can be fed into a KDF, like HKDF-Expand {{!RFC5869}}, or an XOF, like SHAKE {{FIPS202}}. In both cases, domain separation SHOULD be specified, such as the protocol/application name and purpose of the derived key.

When the Balloon output is too large, it can be truncated to the required key size by taking the first portion of the output. For example, taking the first 256 bits of a 512-bit output. Alternatively, a KDF or XOF can be used, as discussed above.

# Security Considerations

Balloon has been proven sequentially memory-hard in the random-oracle model and uses a password-independent memory access pattern to prevent side-channel attacks leaking information about the password {{BCS16}}. However, no function that uses a password-independent memory access pattern can be optimally memory-hard in the parallel setting {{AB16}}. In other words, Balloon is inherently weaker against parallel attacks.

To improve Balloon's resistance to parallel attacks, the output can be fed into a password hashing function with a password-dependent memory access pattern, such as scrypt {{?RFC7914}}. The cost of this approach is like increasing the `timeCost` of Balloon {{BCS16}}. However, even this does not defend against an attacker who can both a) obtain memory access pattern information and b) perform a massively parallel attack; it only protects against the two attacks separately.

The security properties of Balloon depend on the chosen collision-resistant hash function/XOF. For example, a 256-bit hash should provide 128-bit collision resistance and 256-bit (second) preimage resistance. Technically, only preimage resistance is required for password hashing to prevent the attacker learning information about the password from the hash. However, non-collision-resistant hash functions (e.g. MD5 {{?RFC6151}} and SHA-1 {{?RFC6194}}) MUST NOT be used. Such functions are cryptographically weak and unsuitable for new protocols.

If possible, store the password in protected memory and/or erase the password from memory once it is no longer required. Otherwise, an attacker may be able to recover the password from memory or the disk.

The salt MUST be unique. It SHOULD be randomly generated using a cryptographically secure pseudorandom number generator (CSPRNG). However, it MAY be deterministic and predictable if random generation is not possible. It SHOULD be at least 128 bits long and SHOULD NOT exceed 256 bits.

The `spaceCost`, `timeCost`, `parallelism`, and `delta` MUST be carefully chosen to avoid denial-of-service and user frustration whilst ensuring adequate protection against password cracking. Similarly, systems MUST check for overly large user-specified parameters (e.g. passwords) to prevent denial-of-service attacks.

Avoid using hardcoded parameters (e.g. `spaceCost`/`timeCost`) when performing password hashing; these SHOULD be stored as part of the password hash, as described in {{encoding-password-hashes}}. With key derivation, hardcoded parameters are acceptable if protocol versioning is used.

For password hashing, it is RECOMMENDED to encrypt password hashes using an authenticated encryption with associated data (AEAD) scheme {{?RFC5116}} before storage. This forces an attacker to compromise the key, which is stored separately from the database, as well as the database before they can begin password cracking. If the key is compromised but the database is not, it can be rotated without having to reset any passwords.

For key derivation, one can use a pepper (e.g. a key file) with a keyed hash function, like HMAC {{?RFC2104}}, on the password prior to calling Balloon for additional security. It is RECOMMENDED to use a 256-bit pepper.

If performing key derivation for password-based encryption with a non-committing AEAD scheme, be aware of partitioning oracle attacks, which can significantly speed up password guessing {{LGR21}}. These are relevant when a server that knows the key (an oracle) performs password-based decryption for ciphertexts you send and leaks whether decryption was successful (e.g. via an error message or timing side-channel).

Unlike password hashing algorithms such as bcrypt {{PM99}}, which perform many small pseudorandom reads, Balloon is not cache-hard. Whilst there are no known publications on cache-hardness at the time of writing, it is reported to provide better GPU/ASIC resistance than memory-hardness for shorter delays (e.g. < 1000 ms). In such cases, memory bandwidth and CPU cache sizes are bigger bottlenecks than total memory. This makes cache-hard algorithms ideal for authentication scenarios but potentially less suited for key derivation.

Third-party analysis for Balloon can be found in {{RD16}}, {{AB17}}, {{ABP17}}, and {{RD17}}. However, note that there are multiple versions of Balloon, and none of these papers have analysed the version used in real-world implementations.

# IANA Considerations

This document has no IANA actions.

--- back

# Test Vectors

## Balloon-SHA-256

### Test Vector 1

~~~
password: 70617373776f7264

salt: 73616c74

spaceCost: 1

timeCost: 1

delta: 3

hash: eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545
~~~

### Test Vector 2

~~~
password: 68756e7465723432

salt: 6578616d706c6573616c74

spaceCost: 1024

timeCost: 3

delta: 3

hash: 716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb
~~~

### Test Vector 3

~~~
password: 70617373776f7264

salt: 

spaceCost: 3

timeCost: 3

delta: 3

hash: 20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc
~~~

## Balloon-M-SHA-256

### Test Vector 1

~~~
password: 70617373776f7264

salt: 73616c74

spaceCost: 1

timeCost: 1

parallelism: 1

delta: 3

hash: 97a11df9382a788c781929831d409d3599e0b67ab452ef834718114efdcd1c6d
~~~

### Test Vector 2

~~~
password: 70617373776f7264

salt: 73616c74

spaceCost: 1

timeCost: 1

parallelism: 16

delta: 3

hash: a67b383bb88a282aef595d98697f90820adf64582a4b3627c76b7da3d8bae915
~~~

### Test Vector 3

~~~
password: 68756e7465723432

salt: 6578616d706c6573616c74

spaceCost: 1024

timeCost: 3

parallelism: 4

delta: 3

hash: 1832bd8e5cbeba1cb174a13838095e7e66508e9bf04c40178990adbc8ba9eb6f
~~~

### Test Vector 4

~~~
password: 

salt: 73616c74

spaceCost: 3

timeCost: 3

parallelism: 2

delta: 3

hash: f8767fe04059cef67b4427cda99bf8bcdd983959dbd399a5e63ea04523716c23
~~~

# Acknowledgments
{:numbered="false"}

Balloon was designed by Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter.

Thank you to the Rust Crypto contributors for making Balloon implementations interoperable.

