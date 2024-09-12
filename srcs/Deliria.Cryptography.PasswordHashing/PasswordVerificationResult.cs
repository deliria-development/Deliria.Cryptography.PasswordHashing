namespace Deliria.Cryptography.PasswordHashing;

public record PasswordVerificationResult(VerificationResultType ResultType, PasswordHashDto? HashDto = null);

public enum VerificationResultType
{
    Failed,
    Success,
    SuccessAndUpgrade
}