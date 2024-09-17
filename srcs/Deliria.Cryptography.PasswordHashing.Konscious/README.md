# Deliria.Cryptography.PasswordHashing.Konscious

`Deliria.Cryptography.PasswordHashing.Konscious` is a library implementing the password hashing interface from [`Deliria.Cryptography.PasswordHashing`](../../README.md) using the [`Konscious.Security.Cryptography.Argon2`](https://github.com/kmaragon/Konscious.Security.Cryptography?tab=readme-ov-file#konscioussecuritycryptographyargon2) library as the concrete Argon2 algorithm implementation.

By default it uses OWASP's recommended parameters, but you can also take full control of the parameters if desired.

**Disclaimer**: The "verification and upgrade" feature is currently untested. We do not recommend using it in production environments, but you are welcome to experiment with it.

## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
  - [Examples](#hashing-passwords)
* [Implementing Custom Hashers](#implementing-custom-hashers)
* [Contributing](#contributing)

## Installation

To get started, install the [`Deliria.Cryptography.PasswordHashing.Konscious`]() package, which utilizes the `Konscious.Security.Cryptography.Argon2` implementation.

## Usage

To hash passwords, you can use the [`PasswordHasherKonscious`](.\PasswordHasherKonscious.cs) class, which implements the [`IPasswordHasher`](..\Deliria.Cryptography.PasswordHashing\IPasswordHasher.cs) interface. If you are using Dependency Injection, you can register the hasher as follows:

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
For more complex usage take a look at the [`IPasswordHasher`](.\srcs\Deliria.Cryptography.PasswordHashing\IPasswordHasher.cs) interface documentation.

## Implementing Custom Hashers

Refer to [Implementing Custom Hashers](../../README.md#implementing-custom-hashers).

**Contributing**
--------------

We welcome contributions to improve this library! Please feel free to submit issues or pull requests.