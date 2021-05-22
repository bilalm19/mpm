# MPM
[![Test](https://github.com/bilalm19/mpm/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/bilalm19/mpm/actions/workflows/test.yml)
[![CodeQL Analyze](https://github.com/bilalm19/mpm/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)](https://github.com/bilalm19/mpm/actions/workflows/codeql-analysis.yml)

**M**inimal **P**assword **M**anager. An inefficient but potentially secure and simple password manager. You can use the [MPM client](https://github.com/bilalm19/mpmclient) to interact with the server.

Not audited by a security expert.

## Security Model
Each user has a master password which is stored in the database after it has been hashed with salt. All the other secrets, for each user, are encrypted using this master password. 

The hashing algorithm used is the Password Hashing Competition winner, [argon2](https://github.com/P-H-C/phc-winner-argon2). The version used is Argon2id.

The encryption algorithm is AES-256 with GCM-96. This algorithm is similar to what [hashicorp vault](https://www.vaultproject.io) uses for [storing data at rest](https://www.vaultproject.io/docs/internals/security#external-threat-overview).

The user is responsible for creating and remembering their master password. The password can be as long as the user wants, but the maximum possible stength of the encryption algorithm is reached at 32 length (32 bytes). If the length is greater than or equal to 32, the first 32 characters/bytes will be used to encrypt the secrets.
