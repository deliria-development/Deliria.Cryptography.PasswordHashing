namespace Deliria.Cryptography.PasswordHashing.UnitTest;

public record HashExample(InputParams Input, ExtraDataParams? ExtraDataParams, PasswordHashDto Output, string Encoded);