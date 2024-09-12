using System.Text;

namespace Deliria.Cryptography.PasswordHashing;

public static class HashingUtilities
{
    public static byte[] ToBytes(this string password)
    {
        return Encoding.UTF8.GetBytes(password);
    }

    public static byte[] GenerateSalt(int saltSize)
    {
        var salt = new byte[saltSize];
        Random.Shared.NextBytes(salt);
        return salt;
    }

    /// <summary>
    /// Uses the expected hash's parameters to hash an input (probably for verification purposes)
    /// </summary>
    /// <returns>The hash representation</returns>
    public static PasswordHashDto HashPassword(this IPasswordHasher hasher, InputParams input, PasswordHashDto expectedHash)
    {
        return hasher.HashPassword(
            input,
            new ExtraDataParams(expectedHash.Salt, expectedHash.AssociatedData),
            expectedHash.GetHashingParameters()) with { KeyId = expectedHash.KeyId };
    }

    public static DesiredHashingParameters GetHashingParameters(this PasswordHashDto hashDto)
    {
        return new DesiredHashingParameters(hashDto.Parameters, hashDto.Hash.Length);
    }

    public static bool IsHashEqual(this PasswordHashDto dto1, PasswordHashDto dto2)
    {
        return dto1.Hash.SequenceEqual(dto2.Hash);
    }

    public static PasswordHashDto? TryUpgrade(this IPasswordHasher hasher, InputParams input, PasswordHashDto expectedHash,
        HashUpgradeStrategy? upgradeStrategy, ExtraDataParams? newExtraDataParams, byte[]? newKnownSecret)
    {
        upgradeStrategy ??= new HashUpgradeStrategy(UpgradeThresholdType.AllDifficulty, UpgradeOverwriteType.AllValues, OwaspHashParams.Argon2);
        DesiredHashingParameters desiredHashingParameters = upgradeStrategy.HashingParameters;
        
        bool upgradeStrategyRequired = upgradeStrategy.ThresholdType switch
        {
            UpgradeThresholdType.IndividualValue => IsUpgradeByIndividualValue(expectedHash, desiredHashingParameters),
            UpgradeThresholdType.AllValues => IsUpgradeByAllValues(expectedHash, desiredHashingParameters),
            UpgradeThresholdType.AllDifficulty => IsUpgradeByAllValues(expectedHash, desiredHashingParameters),
            _ => throw new ArgumentOutOfRangeException()
        };

        // no upgrade required, and no new extra data or known-secret
        if (!upgradeStrategyRequired && newExtraDataParams == null && newKnownSecret == null)
        {
            return null;
        }

        if (upgradeStrategyRequired)
        {
            desiredHashingParameters = upgradeStrategy.OverwriteType switch
            {
                UpgradeOverwriteType.IndividualValue => UpgradeByIndividualValue(expectedHash, desiredHashingParameters),
                UpgradeOverwriteType.AllValues => desiredHashingParameters,
                _ => throw new ArgumentOutOfRangeException()
            };
        }

        if (newKnownSecret != null)
        {
            input = input with { KnownSecret = newKnownSecret };
        }
        
        newExtraDataParams ??= new ExtraDataParams(expectedHash.Salt, expectedHash.AssociatedData);

        return hasher.HashPassword(input, newExtraDataParams, desiredHashingParameters);
    }
    
    private static DesiredHashingParameters UpgradeByIndividualValue(PasswordHashDto expectedHash, DesiredHashingParameters desiredHashParams)
    {
        PasswordHashType type = desiredHashParams.Parameters.Type;
        int version = Math.Max(expectedHash.Parameters.Version, desiredHashParams.Parameters.Version);
        uint iterations = Math.Max(expectedHash.Parameters.Iterations, desiredHashParams.Parameters.Iterations);
        uint memory = Math.Max(expectedHash.Parameters.Memory, desiredHashParams.Parameters.Memory);
        byte parallelism = Math.Max(expectedHash.Parameters.Parallelism, desiredHashParams.Parameters.Parallelism);
        int hashLength = Math.Max(expectedHash.Hash.Length, desiredHashParams.HashLength);
        
        return new DesiredHashingParameters(
            new HashingParameters(type, version, memory, iterations, parallelism),
            hashLength
            );
    } 

    private static bool IsUpgradeByIndividualValue(PasswordHashDto expectedHash, DesiredHashingParameters desiredHashParams)
    {
        return expectedHash.Parameters.Type != desiredHashParams.Parameters.Type
            || expectedHash.Parameters.Iterations < desiredHashParams.Parameters.Iterations
            || expectedHash.Parameters.Parallelism < desiredHashParams.Parameters.Parallelism
            || expectedHash.Parameters.Memory < desiredHashParams.Parameters.Memory
            || expectedHash.Parameters.Version < desiredHashParams.Parameters.Version
            || expectedHash.Hash.Length < desiredHashParams.HashLength;
    }
    
    private static bool IsUpgradeByAllValues(PasswordHashDto expectedHash, DesiredHashingParameters desiredHashParams)
    {
        return expectedHash.Parameters.Type != desiredHashParams.Parameters.Type
            || expectedHash.Parameters.Iterations < desiredHashParams.Parameters.Iterations
                && expectedHash.Parameters.Parallelism < desiredHashParams.Parameters.Parallelism
                && expectedHash.Parameters.Memory < desiredHashParams.Parameters.Memory
                && expectedHash.Parameters.Version < desiredHashParams.Parameters.Version
            || expectedHash.Hash.Length < desiredHashParams.HashLength;
    }
    
    private static bool IsUpgradeByDifficulty(PasswordHashDto expectedHash, DesiredHashingParameters desiredHashParams)
    {
        var originalDifficulty = expectedHash.Parameters.Iterations * expectedHash.Parameters.Memory * expectedHash.Parameters.Parallelism;
        var newDifficulty = desiredHashParams.Parameters.Iterations * desiredHashParams.Parameters.Memory * desiredHashParams.Parameters.Parallelism;
        
        return expectedHash.Parameters.Type != desiredHashParams.Parameters.Type
               || originalDifficulty < newDifficulty
               || expectedHash.Hash.Length < desiredHashParams.HashLength;
    }
}