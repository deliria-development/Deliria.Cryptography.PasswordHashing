# Deliria.Cryptography.PasswordHashing

`Deliria.Cryptography.PasswordHashing` is a library designed to provide a simplified password hashing procedure using the Argon2 algorithm. It provides user-friendly interfaces and utilities to help you securely hash, store and verify passwords.

By default it encourages OWASP's recommended parameters, but you can also take full control of the parameters if desired.

**Disclaimer**: The "verification and upgrade" feature is currently untested. We do not recommend using it in production environments, but you are welcome to experiment with it.

## Table of Contents
- [Usage](#usage)
  - [Hashing Passwords](#hashing-passwords)
  - [Implementing Custom Hashers](#implementing-custom-hashers)
- [Contributing](#contributing)
- [License](#license)

## Usage

### Hashing Passwords

To get started, install the [`Deliria.Cryptography.PasswordHashing.Konscious`]() package, which utilizes the [`Konscious.Security.Cryptography.Argon2`](https://github.com/kmaragon/Konscious.Security.Cryptography?tab=readme-ov-file#konscioussecuritycryptographyargon2) implementation.

You can read more about it [here](./srcs/Deliria.Cryptography.PasswordHashing.Konscious/README.md).

### Implementing Custom Hashers

If you wish to implement your own password hashing mechanism, you can do so by creating a class that implements the [`IPasswordHasher`](.\srcs\Deliria.Cryptography.PasswordHashing\IPasswordHasher.cs) interface. You can refer to the [`PasswordHasherKonscious`](.\srcs\Deliria.Cryptography.PasswordHashing.Konscious\PasswordHasherKonscious.cs) class for guidance on how to properly wrap an existing implementation.

## Contributing

We welcome contributions to improve this library! Please feel free to submit issues or pull requests.