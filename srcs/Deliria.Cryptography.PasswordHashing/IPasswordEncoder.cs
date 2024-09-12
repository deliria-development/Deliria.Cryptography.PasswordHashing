namespace Deliria.Cryptography.PasswordHashing;

public interface IPasswordHashEncoder<T>
{
    /// <summary>
    /// Encodes the given hash representation into its encoded format
    /// </summary>
    /// <param name="hashDto">The hash representation</param>
    /// <returns>The encoded hash</returns>
    T Encode(PasswordHashDto hashDto);
    /// <summary>
    /// Decodes the given encoded hash into its proper representation
    /// </summary>
    /// <param name="encodedHash">The encoded hash</param>
    /// <returns>The hash representation</returns>
    /// <exception cref="FormatException">This will be thrown whenever an issue is detected with the encoded PHC string</exception>
    PasswordHashDto Decode(T encodedHash);
}