# Deliria.Cryptography.PasswordHashing

Deliria.Cryptography.PasswordHashing is a library designed to simplify password hashing using the Argon2 algorithm. It provides user-friendly interfaces and utilities to help you securely hash and verify passwords.

**Disclaimer**: The "verification and upgrade" feature is currently untested. We do not recommend using it in production environments, but you are welcome to experiment with it.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
  - [Hashing Passwords](#hashing-passwords)
  - [Implementing Custom Hashers](#implementing-custom-hashers)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Installation

To get started, install the `Deliria.Cryptography.PasswordHashing.Konscious` package, which utilizes the `Konscious.Security.Cryptography.Argon2` implementation.

## Usage

### Hashing Passwords

To hash passwords, you can use the `PasswordHasherKonscious` class, which implements the `IPasswordHasher` interface. If you are using Dependency Injection, you can register the hasher as follows:

```cs
builder.Services.AddSingleton<IPasswordHasher, PasswordHasherKonscious>();
```

### Examples

Here is an example demonstrating how to use the password hasher:

```cs
// Create an instance of the password hasher
IPasswordHasher hasher = new PasswordHasherKonscious();

// Prepare the input parameters with the password to be hashed
InputParams input = new InputParams("test-password".ToBytes());

// Hash the password
PasswordHashDto result = hasher.HashPassword(input);

// Verify the hashed password
bool verification = hasher.VerifyPassword(input, result);
Console.WriteLine($"Verified successfully: {verification}");
```

### Implementing Custom Hashers

If you wish to implement your own password hashing mechanism, you can do so by creating a class that implements the `IPasswordHasher` interface. You can refer to the `PasswordHasherKonscious` class for guidance on how to properly wrap an existing implementation.

## Contributing

We welcome contributions to improve this library! Please feel free to submit issues or pull requests.