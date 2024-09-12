namespace Deliria.Cryptography.PasswordHashing;

public readonly ref struct PhcParameter
{
    public PhcParameter(ReadOnlySpan<char> parameterSpan, char kvSeparator)
    {
        IsEmpty = parameterSpan.IsEmpty;
        if (IsEmpty)
        {
            return;
        }
        
        var delimiterIndex = parameterSpan.IndexOf(kvSeparator);
        if (delimiterIndex == -1)
        {
            throw new FormatException($"Key-Value Separator '{kvSeparator}' not found in parameter. Expected format: 'parameterName{kvSeparator}parameterValue'");
        }

        Name = parameterSpan[..delimiterIndex];
        Value = parameterSpan[(delimiterIndex + 1)..];
    }

    public readonly bool IsEmpty;
    public readonly ReadOnlySpan<char> Name;
    public readonly ReadOnlySpan<char> Value;
}