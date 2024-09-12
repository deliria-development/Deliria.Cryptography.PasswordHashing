using Konscious.Security.Cryptography;

namespace Deliria.Cryptography.PasswordHashing.Konscious;

public sealed class PasswordHasherKonscious : IPasswordHasher
{
    public PasswordHashDto HashPassword(InputParams input, ExtraDataParams? extraDataParams, DesiredHashingParameters? desiredHashingParameters)
    {
        desiredHashingParameters ??= OwaspHashParams.Argon2;
        var hashingParams = desiredHashingParameters.Parameters;
        if (hashingParams.Version != 0x13)
        {
            throw new NotImplementedException($"Version '{hashingParams.Version}' is not supported with Konscious' hasher");
        }

        var password = input.Password;
        Argon2 argon2 = hashingParams.Type switch
        {
            PasswordHashType.Argon2Id => new Argon2id(password),
            PasswordHashType.Argon2I => new Argon2i(password),
            PasswordHashType.Argon2D => new Argon2d(password),
            _ => throw new ArgumentOutOfRangeException()
        };
        // input parameters
        argon2.Salt = extraDataParams?.Salt ?? HashingUtilities.GenerateSalt(OwaspHashParams.RecommendedSaltSize);
        argon2.AssociatedData = extraDataParams?.AssociatedData;
        argon2.KnownSecret = input.KnownSecret;
        // hashing parameters
        argon2.MemorySize = (int)hashingParams.Memory;
        argon2.Iterations = (int)hashingParams.Iterations;
        argon2.DegreeOfParallelism = hashingParams.Parallelism;

        var hash = argon2.GetBytes(desiredHashingParameters.HashLength);

        return new PasswordHashDto(hashingParams, null, extraDataParams?.AssociatedData, argon2.Salt, hash);
    }

    public bool VerifyPassword(InputParams input, PasswordHashDto expectedHash)
    {
        var obtainedHash = this.HashPassword(input, expectedHash);
        return expectedHash.IsHashEqual(obtainedHash);
    }

    public PasswordVerificationResult VerifyAndUpgradePassword(
        InputParams input, PasswordHashDto expectedHash, HashUpgradeStrategy? upgradeStrategy, ExtraDataParams? newExtraDataParams, byte[]? newKnownSecret)
    {
        var obtainedHash = this.HashPassword(input, expectedHash);
        if (!expectedHash.IsHashEqual(obtainedHash))
        {
            return new PasswordVerificationResult(VerificationResultType.Failed);
        }

        var upgradedHash = this.TryUpgrade(input, expectedHash, upgradeStrategy, newExtraDataParams, newKnownSecret);
        return new PasswordVerificationResult(upgradedHash == null ? VerificationResultType.Success : VerificationResultType.SuccessAndUpgrade, upgradedHash);
    }
}