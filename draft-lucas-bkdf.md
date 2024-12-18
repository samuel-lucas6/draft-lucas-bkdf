---
title: "Balloon Key Derivation Function (BKDF)"
docname: draft-lucas-bkdf-latest
category: info

ipr: trust200902
keyword: Internet-Draft
submissiontype: IRTF

stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

venue:
  github: "samuel-lucas6/draft-lucas-bkdf"
  latest: "https://samuel-lucas6.github.io/draft-lucas-bkdf/draft-lucas-bkdf.html"

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

  BLAKE3:
    title: "BLAKE3: one function, fast everywhere"
    target: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
    author:
      -
        ins: J. O'Connor
        name: Jack O’Connor
        org: SpaceX
      -
        ins: J-P. Aumasson
        name: Jean-Philippe Aumasson
        org: Taurus SA
      -
        ins: S. Neves
        name: Samuel Neves
        org: University of Coimbra
      -
        ins: Z. Wilcox-O’Hearn
        name: Zooko Wilcox-O’Hearn
        org: Electric Coin Co
    date: 2020

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

  FLLW15:
    title: "Overview of the Candidates for the Password Hashing Competition"
    rc: "Technology and Practice of Passwords. PASSWORDS 2014. Lecture Notes in Computer Science(), vol 9393, pp. 3–18"
    target: https://doi.org/10.1007/978-3-319-24192-0_1
    author:
      -
        ins: C. Forler
        name: Christian Forler
        org: Bauhaus-Universität Weimar
      -
        ins: E. List
        name: Eik List
        org: Bauhaus-Universität Weimar
      -
        ins: S. Lucks
        name: Stefan Lucks
        org: Bauhaus-Universität Weimar
      -
        ins: J. Wenzel
        name: Jakob Wenzel
        org: Bauhaus-Universität Weimar
    date: 2015

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

--- abstract

This document specifies the Balloon key derivation function (BKDF) for password hashing and password-based key derivation. It is memory-hard, resistant to cache-timing attacks, easy to implement, and can be instantiated using any collision-resistant pseudorandom function (PRF), hash function, or extendable-output function (XOF).

--- middle

# Introduction

BKDF is a memory-hard password hashing and password-based key derivation function based on Balloon {{BCS16}}, an algorithm published shortly after the Password Hashing Competition (PHC). Here is how it compares to prior password hashing algorithms that are widely used in practice:

|                      | PBKDF2 | bcrypt | scrypt | Argon2  | BKDF |
|:--------------------:|:------:|:------:|:------:|:-------:|:----:|
| Memory-hard          | No     | No     | Yes    | Yes     | Yes  |
| Cache-hard           | No     | Yes    | No     | No      | No   |
| Parallelism          | No     | No     | Yes    | Yes     | Yes  |
| Resists cache-timing | N/A    | No     | No     | Depends | Yes  |
| Single primitive     | Yes    | Yes    | No     | No      | Yes  |
| Mode of operation    | Yes    | No     | No     | No      | Yes  |
| Intuitive design     | No     | No     | No     | No      | Yes  |
| No variants          | Yes    | Yes    | Yes    | No      | Yes  |
| Key derivation       | Yes    | No     | Yes    | Yes     | Yes  |
| Separate memory/time | No     | No     | No     | Yes     | Yes  |
| Pepper               | No     | No     | No     | Yes     | Yes  |
| Associated data      | No     | No     | No     | Yes     | Yes  |
| Personalization      | No     | No     | No     | No      | Yes  |

In sum, it shares many features with Argon2 {{?RFC9106}}, the PHC winner, whilst being more of a spiritual successor to PBKDF2 {{?RFC8018}}. Namely, the design is simple and supports any collision-resistant PRF, hash function, or XOF, allowing easy implementation with existing APIs and NIST approved functions to be used.

## Comparison to Balloon

BKDF exists because the Balloon paper does not fully specify the algorithm, the performance is suboptimal, there are anonymity/security issues with the design, there are multiple variants, and functionality like support for key derivation is missing. These factors have limited its adoption and led to incompatible implementations.

This document rectifies these issues and more by improving the performance, specifying an encoding, preventing canonicalization attacks, improving domain separation, not computing the memory access pattern from the salt, fixing the modulo bias, making delta a constant, treating Balloon and Balloon-M as one algorithm, and adding support for key derivation, a pepper, associated data, a personalization string, and keyed hashing like HMAC {{!RFC2104}}.

Importantly, the approach to memory hardness remains the same, meaning such analyses of Balloon should transfer to BKDF. Furthermore, the security of collision-resistant hash functions that will be used in BKDF is well understood. Therefore, assuming these functions are being used correctly, the design is secure.

Note that this document is not an IETF product and is not a standard.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Throughout this document, "byte" refers to the same unit as "octet", namely an 8-bit sequence.

Operations:

- `x++`: incrementing the integer `x` by 1 after it has been used in a function.
- `x ** y`: integer `x` to the power of `y`.
- `x % y`: the remainder when dividing `x` by `y`.
- `a ^ b`: the bitwise XOR of `a` and `b`.
- `a || b`: the concatenation of `a` and `b`.
- `a[i]`: index `i` of array `a`.
- `a.Length`: the length of `a` in bytes.
- `a.Slice(i, l)`: the copy of `l` bytes from byte array `a`, starting at index `i`.
- `ByteArray(l)`: the creation of a new byte array with length `l`.
- `BlockArray(n, l)`: the creation of a new array of arrays containing `n` byte arrays, each with length `l`.
- `PRF(k, m)`: the output of a collision-resistant PRF (e.g. HMAC-SHA512 {{!RFC2104}}) with key `k` and message `m`, both byte arrays. If the collision-resistant hash function supports a key parameter (e.g. BLAKE2b {{!RFC7693}}), that parameter MUST be used. Otherwise, if there is no key parameter (e.g. SHA-512 {{!RFC6234}}), you MUST perform prefix MAC and pad the key with zeros to the block size (1024 bits for SHA-512).
- `LE32(x)`: the little-endian encoding of unsigned 32-bit integer `x`.
- `LE64(x)`: the little-endian encoding of unsigned 64-bit integer `x`.
- `ReadLE32(a)`: the little-endian conversion of byte array `a` into an unsigned 32-bit integer.
- `ZeroPad(a, n)`: byte array `a` padded with zeros until it is `n` bytes long. If `a` is already `n` bytes long, no padding is performed.
- `Ceiling(x)`: the floating-point number `x` rounded up to the nearest whole number.
- `UTF8(s)`: the UTF-8 {{!RFC3629}} encoding of string `s`.

Constants:

- `HASH_LEN`: the output length of the hash function in bytes. For an XOF, this MUST be the nearest power of 2 to the block size (e.g. 128 bytes for SHAKE128 {{FIPS202}} and 64 bytes for BLAKE3 {{BLAKE3}}).
- `KEY_LEN`: the length of the PRF key in bytes. This MUST be the length of whichever is shortest: the hash function block size or the maximum PRF key size. For example, 128 bytes for HMAC-SHA512 and SHA-512 (the block size) but 64 bytes for BLAKE2b and 32 bytes for BLAKE3 (the maximum key parameter size).
- `VERSION`: the version of the algorithm specified in this document, which is 1 as an integer.
- `MAX_PASSWORD`: the maximum password length, which is 4294967295 bytes.
- `MAX_SALT`: the maximum salt length, which is 4294967295 bytes.
- `MIN_PERSONALIZATION`: the minimum personalization length, which is 2 bytes.
- `MAX_PERSONALIZATION`: the maximum personalization length, which is 4294967295 bytes.
- `MIN_SPACECOST`: the minimum space cost, which is 0 as an integer.
- `MAX_SPACECOST`: the maximum space cost, which is 32 as an integer.
- `MIN_TIMECOST`: the minimum time cost, which is 1 as an integer.
- `MAX_TIMECOST`: the maximum time cost, which is 16777215 as an integer.
- `MIN_PARALLELISM`: the minimum parallelism, which is 1 as an integer.
- `MAX_PARALLELISM`: the maximum parallelism, which is 16777215 as an integer.
- `MAX_LENGTH`: the maximum output length, which is 4294967295 as an integer.
- `MAX_ASSOCIATED_DATA`: the maximum associated data length, which is 4294967295 bytes.

# The BKDF Algorithm

~~~
BKDF(password, salt, personalization, spaceCost, timeCost, parallelism, length, pepper, associatedData)
~~~

BKDF calls an internal function that provides memory hardness in a way that supports parallelism and then produces a variable-length output. It can be divided into three steps:

1. KDF Extract: a key is derived from the password, salt, personalization, pepper, and associated data.
2. Parallelism: the internal function, which uses the derived key as well as other user-provided parameters, is called in parallel, and the outputs are XORed together.
3. KDF Expand: a KDF in feedback mode is used to derive key material for the user from the derived key, context information, and the XORed outputs.

Note that the internal function calls SHOULD be implemented in parallel, not serially. Otherwise, the `parallelism` parameter essentially becomes another `timeCost` parameter. Therefore, if multithreading is not possible, it is RECOMMENDED to only support a `parallelism` of 1.

Inputs:

- `password`: the password to be hashed, which MUST NOT be greater than `MAX_PASSWORD` bytes long.
- `salt`: the unique and non-secret salt, which MUST NOT be greater than `MAX_SALT` bytes long.
- `personalization`: the hardcoded, globally unique, and application-specific personalization string for the entire database/application, which MUST be between `MIN_PERSONALIZATION` and `MAX_PERSONALIZATION` bytes long.
- `spaceCost`: the memory size in `2 ** spaceCost` blocks, where a block is `HASH_LEN` bytes long. It MUST be an integer between `MIN_SPACECOST` and `MAX_SPACECOST`.
- `timeCost`: the number of rounds, which MUST be an integer between `MIN_TIMECOST` and `MAX_TIMECOST`.
- `parallelism`: the number of CPU cores/internal function calls in parallel, which MUST be an integer between `MIN_PARALLELISM` and `MAX_PARALLELISM`.
- `length`: the length of the password hash/derived key in bytes, which MUST NOT be greater than `MAX_LENGTH`.
- `pepper`: an optional secret key, which MUST NOT be greater than `KEY_LEN` bytes long.
- `associatedData`: optional context information, which MUST NOT be greater than `MAX_ASSOCIATED_DATA` bytes long.

Outputs:

- The password hash/derived key, which is `length` bytes long.

Steps:

~~~
outputs = BlockArray(parallelism, HASH_LEN)

if pepper.Length == 0
    key = ByteArray(0)
else
    key = pepper
key = ZeroPad(key, KEY_LEN)

key = PRF(key, password || salt || personalization || associatedData || LE32(pepper.Length) || LE32(password.Length) || LE32(salt.Length) || LE32(personalization.Length) || LE32(associatedData.Length))
key = ZeroPad(key, KEY_LEN)

parallel for i = 0 to parallelism - 1
    outputs[i] = BalloonCore(key, personalization, spaceCost, timeCost, parallelism, i + 1)

hash = ByteArray(HASH_LEN)
foreach output in outputs
    for i = 0 to output.Length - 1
        hash[i] = hash[i] ^ output[i]

counter = 1
reps = Ceiling(length / HASH_LEN)
previous = hash
result = ByteArray(0)
for i = 0 to reps - 1
    previous = PRF(key, previous || UTF8("bkdf") || LE32(counter++))
    result = result || previous

return result.Slice(0, length)
~~~

# The BalloonCore Function

~~~
BalloonCore(key, personalization, spaceCost, timeCost, parallelism, iteration)
~~~

The BalloonCore function is the internal function used by BKDF for memory hardness. It can be divided into four steps:

1. Precompute: the user-provided parameters and domain separation are used to precompute pseudorandom bytes for the password-independent memory accesses performed in step 3.
2. Expand: a large buffer is filled with pseudorandom bytes derived by hashing user-provided parameters and domain separation before repeatedly hashing the previous output.
3. Mix: the buffer is mixed for the number of rounds specified by the user. Each hash-sized block becomes equal to the hash of the previous block, the current block, and delta other blocks pseudorandomly chosen from the buffer.
4. Extract: the last block of the buffer is output for key derivation.

Inputs:

- `key`: the key from the BKDF algorithm.
- `personalization`: the personalization provided to the BKDF algorithm.
- `spaceCost`: the space cost provided to the BKDF algorithm.
- `timeCost`: the time cost provided to the BKDF algorithm.
- `parallelism`: the parallelism provided to the BKDF algorithm.
- `iteration`: the parallelism loop iteration from the BKDF algorithm.

Outputs:

- The last block of the buffer, which is `HASH_LEN` bytes long.

Steps:

~~~
spaceCost = 2 ** spaceCost
buffer = BlockArray(spaceCost, HASH_LEN)

counter = 0
emptyKey = ZeroPad(ByteArray(0), KEY_LEN)
pseudorandom = ByteArray(0)
reps = (spaceCost * timeCost * 3) / (HASH_LEN / 4)
for i = 0 to reps - 1
    pseudorandom = pseudorandom || PRF(emptyKey, LE32(VERSION) || personalization || LE32(spaceCost) || LE32(timeCost) || LE32(parallelism) || LE32(iteration) || LE64(counter++))

buffer[0] = PRF(key, LE32(VERSION) || LE32(spaceCost) || LE32(timeCost) || LE32(parallelism) || LE32(iteration) || LE64(counter++))
for m = 1 to spaceCost - 1
    buffer[m] = PRF(key, buffer[m - 1] || LE64(counter++))

offset = 0
previous = buffer[spaceCost - 1]
for t = 0 to timeCost - 1
    for m = 0 to spaceCost - 1
        other1 = ReadLE32(pseudorandom.Slice(offset, 4)) % spaceCost
        other2 = ReadLE32(pseudorandom.Slice(offset + 4, 4)) % spaceCost
        other3 = ReadLE32(pseudorandom.Slice(offset + 8, 4)) % spaceCost
        buffer[m] = PRF(key, previous || buffer[m] || buffer[other1] || buffer[other2] || buffer[other3] || LE64(counter++))
        previous = buffer[m]
        offset = offset + 12

return previous
~~~

# Implementation Considerations

There are several ways to optimise the pseudocode, which is written for readability:

- Instead of using an array of byte arrays for the buffer, access portions of a single large byte array.
- Create a single buffer full of zeros for the zero padding rather than padding two variables separately.
- Instead of an integer counter that gets repeatedly converted to a byte array, allocate a byte array once and repeatedly fill that buffer or use a byte array counter.
- Instead of `x % spaceCost`, one can do `x & (spaceCost - 1)` because `spaceCost` is a power of 2.
- Skip the XORing of outputs when `parallelism = 1`.
- Instead of `Ceiling(length / HASH_LEN)`, one can do `(length + HASH_LEN - 1) / HASH_LEN`.
- Convert constants/unchanging values to bytes once rather than in each loop iteration or in multiple loops.
- Use an incremental hash function API rather than manual concatenation.
- If possible with the hash function API, cache the hash function state after processing fixed values (e.g. the key) so they do not need to be processed again.

# Choosing the Hash Function

The choice of collision-resistant hash function affects the performance and security of BKDF in three ways:

1. For the same parameters, the attacker has an advantage if the algorithm is faster in hardware versus software. They will be able to do the computation in less time than the defender.
2. For the same delay, the defender will be forced to use smaller parameters with a slower collision-resistant hash function in software. Using a faster algorithm in software means stronger parameters can be used.
3. A smaller output length worsens the performance and memory-hardness.

It is RECOMMENDED to use a collision-resistant hash function with a larger output length that is fast in software but relatively slow in hardware, such as BLAKE2b-512 {{!RFC7693}}. As another example, SHA-512 is preferable to SHA-256 {{!RFC6234}}.

SHA-3 {{FIPS202}} is NOT RECOMMENDED as it is slower in software compared to in hardware. HMAC {{!RFC2104}} is also NOT RECOMMENDED because it increases the number of calls to the chosen hash function.

# Choosing the Cost Parameters

The higher the `spaceCost` and `timeCost`, the longer it takes to compute an output. If these values are too small, security is unnecessarily reduced. If they are too large, there is a risk of user frustration and denial-of-service for different types of user devices and servers. To make matters even more complicated, these parameters may need to be increased over time as hardware gets faster/smaller.

The purpose of `parallelism` is to enable greater memory hardness without increasing the delay. This is because the mixing is done by multiple CPU cores simultaneously rather than serially. However, a poor choice of `parallelism` can also cause denial-of-service or give the attacker an advantage.

The following procedure can be used to choose parameters:

1. For performing authentication on a server or running the algorithm on any type of user device, set the `parallelism` to 1. This avoids resource exhaustion attacks and slowdowns on machines with few CPU cores. Otherwise, set it to the maximum number of CPU cores the machine can dedicate to the computation (e.g. 4 cores).
2. Establish the maximum acceptable delay for the user. For example, 100-500 ms for authentication, 250-1000 ms for file encryption, and 1000-5000 ms for disk encryption. On servers, you also need to factor in the maximum number of authentication attempts per second.
3. Determine the maximum amount of memory available, taking into account different types of user devices and denial-of-service. For instance, mobile phones versus laptops/desktops.
4. Convert the closest MiB/GiB memory size that is a power of 2 to bytes. Then set `spaceCost` to `log2(bytes / HASH_LEN)`, which converts the number of BKDF blocks to an integer between `MIN_SPACECOST` and `MAX_SPACECOST`.
5. Find the `timeCost` that brings you closest to the maximum acceptable delay or target number of authentication attempts per second by running benchmarks.
6. If `timeCost` is only 1, reduce `spaceCost` to be able to increase `timeCost`. Performing multiple rounds is beneficial for security {{AB17}}.

To cause an attacker to get < 10 kH/s on an RTX 4080 SUPER GPU, the parameters must be at least one of the following when using SHA-256, SHA-512, HMAC-SHA256, or HMAC-SHA512 as the collision-resistant PRF:

- SHA-256: `m=256 KiB, t=48` or `m=512 KiB, t=24` or `m=1 MiB, t=12` or `m=2 MiB, t=6`
- SHA-512: `m=256 KiB, t=34` or `m=512 KiB, t=17` or `m=1 MiB, t=9` or `m=2 MiB, t=4`
- HMAC-SHA256: `m=256 KiB, t=36` or `m=512 KiB, t=18` or `m=1 MiB, t=9` or `m=2 MiB, t=5`
- HMAC-SHA512: `m=256 KiB, t=26` or `m=512 KiB, t=13` or `m=1 MiB, t=7` or `m=2 MiB, t=3`

Note that these are example minimum parameters at the time of writing. They will not be appropriate minimums in the future, and you SHOULD use stronger parameters if you can afford to.

See {{security-considerations}} for guidance on the other parameters.

# Encoding Password Hashes

To store BKDF hashes in a database as strings, the following format SHOULD be used:

~~~
$bkdf-hash$v=version$m=spaceCost,t=timeCost,p=parallelism$salt$hash
~~~

- `bkdf-hash`: where `hash` is the official hash function OID (from an RFC or NIST) minus any prefix (e.g. `id-`). For example, `blake2b512` for BLAKE2b-512 {{!RFC7693}}.
- `v=version`: the current BKDF version is specified by the `VERSION` constant. If the design is modified after publication, the version will be incremented.
- `m=spaceCost`: the space cost as a number, not the memory size in blocks or KiB.
- `t=timeCost`: the number of rounds.
- `p=parallelism`: the number of CPU cores/internal function calls in parallel.
- `salt`: the salt encoded in Base64 with no padding {{!RFC4648}}.
- `hash`: the full/untruncated BKDF output encoded in Base64 with no padding {{!RFC4648}}. See {{security-considerations}} for guidance on the length.

Here is an example encoded hash:

~~~
$bkdf-sha256$v=1$m=32,t=3,p=1$ZXhhbXBsZXNhbHQ$cWBD3/d3tEqnuI3LqxLAeKvs+snSicW1GVlnqmNEDfs
~~~

# Security Considerations

## Usage Guidelines

Technically, only preimage resistance is required for password hashing to prevent the attacker learning information about the password from the hash. However, hash functions that are not collision resistant (e.g. MD5 {{?RFC6151}} and SHA-1 {{?RFC6194}}) MUST NOT be used. Such functions are cryptographically weak and unsuitable for new protocols.

It is RECOMMENDED to either restrict password characters to ASCII {{?RFC20}} or to apply Unicode Normalization Form C (NFC) {{?RFC8265}} to the password prior to UTF-8 encoding {{!RFC3629}}. The former eliminates and the latter reduces the risk of password characters being encoded differently depending on the keyboard, operating system, and so on. Without taking these steps, a user might not always be able to log in, decrypt a file/disk, etc.

If possible, store the password in protected memory and/or erase the password from memory once it is no longer required. Otherwise, an attacker may be able to recover the password from memory or the disk.

In all cases, it is RECOMMENDED to use a 128-bit `salt`. However, a 64-bit `salt` MAY be used if there are storage constraints. Regardless, the `salt` length SHOULD NOT vary in your protocol/application.

The salt MUST be unique each time you call the function unless verifying a password hash or deriving the same key. It SHOULD be randomly generated using a cryptographically secure pseudorandom number generator (CSPRNG). However, it MAY be deterministic and predictable if random generation is not possible.

The salt SHOULD be considered a non-secret value. It SHOULD be stored alongside the password hash for password hashing (see {{encoding-password-hashes}}) or in something like a file header for key derivation. If you have a secret key, the password hash SHOULD be encrypted or the `pepper` parameter SHOULD be used, as described below.

The `personalization` parameter MUST be a hardcoded, globally unique, and application-specific string for your entire database/application. A good default format is `UTF8("[application] [commit timestamp] [purpose]")`. For instance, `"example.com 2024-11-03 14:36:48 password hashing"`. This binds the buffer, memory access pattern, and output to your application even if multiple applications have the same name, which helps hinder attackers. It MUST NOT be unique per user in the database/application; that is the purpose of the salt.

The `spaceCost`, `timeCost`, and `parallelism` parameters MUST be carefully chosen to avoid denial-of-service and user frustration whilst ensuring adequate protection against password cracking. See {{choosing-the-cost-parameters}} for more information about choosing these parameters.

Avoid using hardcoded `spaceCost`/`timeCost`/`parallelism` parameters when performing password hashing; these SHOULD be stored as part of the password hash, as described in {{encoding-password-hashes}}. With key derivation, hardcoded parameters are acceptable if protocol versioning is used.

For password hashing, it is RECOMMENDED to use a `length` of 128 or 256 bits. For key derivation, it is RECOMMENDED to use a `length` of at least 128 bits.

If you want to derive multiple keys (e.g. for encryption and authentication), you MUST only run the algorithm once and use different portions of the output as separate keys. Otherwise, the attacker may have an advantage, like only needing to run the algorithm once instead of twice to check a password, and you will be forced to use weaker parameters.

For password hashing, it is RECOMMENDED to encrypt password hashes using an unauthenticated encryption algorithm or an authenticated encryption with associated data (AEAD) scheme {{?RFC5116}} before storage. This forces an attacker to compromise the key, which is stored separately from the database, as well as the database before they can begin password cracking. If the key is compromised but the database is not, it can be rotated without having to reset any passwords. It is RECOMMENDED to use a 256-bit key.

For key derivation, one can feed a secret key into the `pepper` parameter for additional security. This forces an attacker to compromise the pepper before they can guess the password. It is RECOMMENDED to use a 256-bit pepper.

To bind context information to the output, like a user ID and server ID for password-authenticated key exchange (PAKE) algorithms, the `associatedData` parameter can be used. However, in most cases, this parameter is not required.

Importantly, if multiple values are concatenated to form the `associatedData` parameter, they MUST be unambiguously encoded. For example, by using fixed-length values or by prepending/appending the little-endian encoded length of each value.

## Security Guarantees

The security properties of BKDF depend on the chosen collision-resistant hash function. For example, a 256-bit hash typically provides 128-bit collision resistance and 128- or 256-bit (second) preimage resistance.

Balloon has been proven sequentially memory-hard in the random-oracle model, making it resistant against sequential GPU/ASIC attacks {{BCS16}}. An adversary trying to save space pays a large penalty in computation time.

Balloon also uses a password-independent memory access pattern to prevent side-channel attacks leaking information about the password {{BCS16}}. This property is especially relevant in cloud computing environments where multiple users can share the same physical machine. However, no function that uses a password-independent memory access pattern can be optimally memory-hard in the parallel setting.

BKDF is not vulnerable to garbage-collector attacks since the internal state is overwritten {{FLLW15}}. However, it can be vulnerable to weak garbage-collector attacks because the key derived from the password is kept in memory throughout the algorithm. Even if you cache the hash function state after processing the key and zero the key, this attack is still possible. The only prevention is to use a pepper and zero that from memory immediately after processing it. With that said, the password is likely to remain in memory anyway, rendering this attack unnecessary.

The approach to parallelism is subject to a tradeoff, namely an adversary can do sequential calls to the BalloonCore function to avoid increasing the memory usage, keeping the time-area product constant. This is deemed acceptable because parallelism is often not used in practice and avoiding this would complicate the design.

Unlike password hashing algorithms such as bcrypt {{PM99}}, which perform many small and fast pseudorandom reads, BKDF is not cache-hard. Whilst there are no known publications on cache-hardness at the time of writing, it is reported to provide better GPU resistance than memory-hardness for shorter delays (e.g. < 1000 ms). This is because such algorithms force GPUs to use less memory bandwidth because of their large bus width (typically 256 to 1024 bits). Assuming GPUs are primarily used for password cracking, this makes cache-hard algorithms ideal for authentication scenarios especially.

Third-party analysis of Balloon can be found in {{RD16}}, {{AB17}}, {{ABP17}}, and {{RD17}}. However, note that there are multiple versions of Balloon, and none of these papers have analysed BKDF.

# IANA Considerations

This document has no IANA actions.

--- back

# Test Vectors

## BKDF-SHA256

NOTE: These test vectors are out of date and will be updated when the new design has been finalised.

### Test Vector 1

~~~ test-vectors
password: 70617373776f7264

salt: 73616c74

spaceCost: 1

timeCost: 1

parallelism: 1

hash: 97a11df9382a788c781929831d409d3599e0b67ab452ef834718114efdcd1c6d
~~~

### Test Vector 2

~~~ test-vectors
password: 70617373776f7264

salt: 73616c74

spaceCost: 1

timeCost: 1

parallelism: 16

hash: a67b383bb88a282aef595d98697f90820adf64582a4b3627c76b7da3d8bae915
~~~

### Test Vector 3

~~~ test-vectors
password: 68756e7465723432

salt: 6578616d706c6573616c74

spaceCost: 1024

timeCost: 3

parallelism: 4

hash: 1832bd8e5cbeba1cb174a13838095e7e66508e9bf04c40178990adbc8ba9eb6f
~~~

### Test Vector 4

~~~ test-vectors
password:

salt: 73616c74

spaceCost: 3

timeCost: 3

parallelism: 2

hash: f8767fe04059cef67b4427cda99bf8bcdd983959dbd399a5e63ea04523716c23
~~~

# Acknowledgments
{:numbered="false"}

The original version of Balloon was designed by Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter.

We would like to thank the following individuals for their contributions:

- Henry Corrigan-Gibbs and Steve Thomas for their help with the new design and feedback on this document.
- Jeremiah Blocki and rmlibre for explaining the pros and cons of having the memory access pattern depend on the salt.
- daxpedda for highlighting the importance of supporting serial parallelism.
