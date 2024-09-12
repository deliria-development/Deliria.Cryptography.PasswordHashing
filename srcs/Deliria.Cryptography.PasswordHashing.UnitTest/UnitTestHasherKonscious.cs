using Deliria.Cryptography.PasswordHashing.Konscious;

namespace Deliria.Cryptography.PasswordHashing.UnitTest;

public class UnitTestHasherKonscious
{
    private readonly IPasswordHasher _hasher = new PasswordHasherKonscious();
    private static readonly HashExample[] CorrectArgonHashes = HashExamples.Argon;
    
    [Fact]
    public void TestHashing()
    {
        var actions = new Action[CorrectArgonHashes.Length];
        for (var index = 0; index < CorrectArgonHashes.Length; index++)
        {
            var (input, extra, hashDto, _) = CorrectArgonHashes[index];
            actions[index] = () =>
            {
                var result = _hasher.HashPassword(input, extra, hashDto.GetHashingParameters());
                Assert.Equal(hashDto, result with { KeyId = hashDto.KeyId });
            };
        }

        Assert.Multiple(actions);
    }
    
    [Fact]
    public void TestVerification()
    {
        var actions = new Action[CorrectArgonHashes.Length];
        for (var index = 0; index < CorrectArgonHashes.Length; index++)
        {
            var (input, _, hashDto, _) = CorrectArgonHashes[index];
            actions[index] = () =>
            {
                Assert.True(_hasher.VerifyPassword(input, hashDto));
            };
        }

        Assert.Multiple(actions);
    }
    
    /*[Fact]
    public void TestVerificationAndUpgrade()
    {
        var actions = new Action[CorrectArgonHashes.Length];
        for (var index = 0; index < CorrectArgonHashes.Length; index++)
        {
            var (input, _, hashDto, _) = CorrectArgonHashes[index];
            actions[index] = () =>
            {
                var result = _hasher.VerifyAndUpgradePassword(input, hashDto);
                Assert.True(result.ResultType is VerificationResultType.Success or VerificationResultType.SuccessAndUpgrade);
            };
        }

        Assert.Multiple(actions);
    }*/
}