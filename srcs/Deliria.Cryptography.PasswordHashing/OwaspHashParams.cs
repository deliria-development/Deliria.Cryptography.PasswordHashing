namespace Deliria.Cryptography.PasswordHashing;

public static class OwaspHashParams
{
    public const int RecommendedSaltSize = 16;
    public const int RecommendedHashSize = 128;
    
    public static readonly DesiredHashingParameters Argon2 = new(
        new HashingParameters(PasswordHashType.Argon2Id, 0x13, 7*1024, 5, 1),
        RecommendedHashSize);
}