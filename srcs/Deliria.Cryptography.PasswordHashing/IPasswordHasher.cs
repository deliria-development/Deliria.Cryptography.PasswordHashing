using System.ComponentModel.DataAnnotations;

namespace Deliria.Cryptography.PasswordHashing;

public interface IPasswordHasher
{
    /// <summary>
    /// Takes the parameters and computes a hash
    /// </summary>
    /// <param name="input">The input required to compute the hash</param>
    /// <param name="extraDataParams">Optional, extra data to compute the hash</param>
    /// <param name="desiredHashingParameters">Optional, defines hashing parameters, if omitted one of the OWASP recommended presets will be used.</param>
    /// <returns>The hash representation</returns>
    /// <exception cref="NotImplementedException">When for there is a reason the parameters can't be handled by the implementation</exception>
    PasswordHashDto HashPassword(InputParams input, ExtraDataParams? extraDataParams = null, DesiredHashingParameters? desiredHashingParameters = null);
    
    /// <summary>
    /// Takes both the parameters and an already known hash to perform a verification of their equality
    /// </summary>
    /// <param name="input">The input required to compute the hash</param>
    /// <param name="expectedHash">The known hash representation</param>
    /// <returns>True if the verification was successful, else false</returns>
    /// <exception cref="NotImplementedException">When for there is a reason the parameters can't be handled by the implementation</exception>
    bool VerifyPassword(InputParams input, PasswordHashDto expectedHash);

    /// <summary>
    /// Takes both the parameters and an already known hash to perform a verification of their equality
    /// </summary>
    /// <param name="input">The input required to compute the hash</param>
    /// <param name="expectedHash">The known hash representation</param>
    /// <param name="upgradeStrategy">Optional, defines the currently desired hashing parameters and upgrade strategy, if omitted one of the OWASP recommended presets will be used.</param>
    /// <param name="newExtraDataParams">Optional, defines the new salt or associated data</param>
    /// <param name="newKnownSecret">>Optional, defines the new secret</param>
    /// <returns>Can return a verification result or a</returns>
    /// <exception cref="NotImplementedException">When for there is a reason the parameters can't be handled by the implementation</exception>
    PasswordVerificationResult VerifyAndUpgradePassword(
        InputParams input, PasswordHashDto expectedHash, HashUpgradeStrategy? upgradeStrategy = null, ExtraDataParams? newExtraDataParams = null, byte[]? newKnownSecret = null);
}

/// <param name="salt">
///     Optional, will be filled automatically if not provided.
///     Makes each user's input more unique by adding extra entropy to its input
///     (aka. makes <see href="https://en.wikipedia.org/wiki/Rainbow_table">Rainbow Table attacks</see> less effective).
///     The <see href="https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding">PHC specification</see>:
///     requires a minimum length of 8 bytes, suggests a maximum length of 48 bytes to allow performing the parsing through stack allocation
///     and recommends using a UUID implementation or a CSPRNG for the generation of salts.
/// </param>
/// <param name="associatedData">
///     Optional, non-secret data that adds extra "uniqueness" to each hash (more or less performs an auxiliary job to parameter "Salt"; normally this parameter would be overkill).
///     The <see href="https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding">PHC specification</see> suggests a maximum length of 32 bytes.
/// </param>
public readonly struct ExtraDataParams(
    [MinLength(8)] [MaxLength(48)] byte[] salt,
    [MaxLength(32)] byte[]? associatedData = null)
{
    [MinLength(8)] [MaxLength(48)]
    public byte[] Salt { get; } = salt;
    [MaxLength(32)]
    public byte[]? AssociatedData { get; } = associatedData;
}

/// <param name="Password">Required, the password representation in a binary format.</param>
/// <param name="KnownSecret">
///     Optional, secret data that will make reverse engineering the hash more hard
///     (take into account that <see href="https://en.wikipedia.org/wiki/Security_through_obscurity">Security through obscurity</see>
///     is not the way to go; but more the merrier, right?).
/// </param>
public record InputParams(byte[] Password, byte[]? KnownSecret = null);

/// <param name="Parameters">Optional, defines hashing parameters</param>
/// <param name="HashLength">Optional, defines the desired hash length</param>
public record DesiredHashingParameters(HashingParameters Parameters, int HashLength);

public record HashUpgradeStrategy(UpgradeThresholdType ThresholdType, UpgradeOverwriteType OverwriteType, DesiredHashingParameters HashingParameters);

public enum UpgradeThresholdType
{
    /** The upgrade will be triggered if any value is lower than the ones in the provided <see cref="DesiredHashingParameters"/> */
    IndividualValue,
    /** The upgrade will be triggered if all values are lower than the ones in the provided <see cref="DesiredHashingParameters"/> */
    AllValues,
    /** The upgrade will be triggered if the difficulty (m*t*p)  */
    AllDifficulty
}

public enum UpgradeOverwriteType
{
    /** Will only overwrite those values that are respectively lower than the ones in the provided <see cref="DesiredHashingParameters"/> */
    IndividualValue,
    /** Will overwrite all the values with the ones provided in <see cref="DesiredHashingParameters"/> */
    AllValues
}