namespace Deliria.Cryptography.PasswordHashing.UnitTest;

public class UnitTestPhcEncoder
{
    private readonly IPasswordHashEncoder<string> _encoder = new PhcPasswordEncoder();
    private static readonly HashExample[] ArgonHashes = HashExamples.Argon;
    
    [Fact]
    public void TestDecode()
    {
        var actions = new Action[ArgonHashes.Length];
        for (var index = 0; index < ArgonHashes.Length; index++)
        {
            var (_, _, hashDto, encodedString) = ArgonHashes[index];
            actions[index] = () =>
            {
                var decodedResult = _encoder.Decode(encodedString);
                Assert.Equal(hashDto, decodedResult);
            };
        }

        Assert.Multiple(actions);
    }
    
    [Fact]
    public void TestEncode()
    {
        var actions = new Action[ArgonHashes.Length];
        for (var index = 0; index < ArgonHashes.Length; index++)
        {
            var (_, _, hashDto, encodedString) = ArgonHashes[index];
            actions[index] = () =>
            {
                var encodedResult = _encoder.Encode(hashDto);
                Assert.Equal(encodedResult, encodedString);
            };
        }

        Assert.Multiple(actions);
    }
}