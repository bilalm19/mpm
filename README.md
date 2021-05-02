# MPM
**M**inimal **P**assword **M**anager. An inefficient but potentially secure and simple password manager.

Not audited by a security expert.

## Security Model
Each user has a master password which is stored in the database after it has been hashed with salt. All the other secrets, for each user, are encrypted using this master password. The encryption algorithm is AES-256 with GCM-96. This algorithm is similar to what [hashicorp vault](https://www.vaultproject.io) uses for [storing data at rest](https://www.vaultproject.io/docs/internals/security#external-threat-overview).

The user is responsible for creating and remembering their master password. The password can be as long as the user wants, but the maximum possible stength of the encryption algorithm is reached at 32 length (32 bytes).
