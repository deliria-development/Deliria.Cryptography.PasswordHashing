namespace Deliria.Cryptography.PasswordHashing;

public class PhcPasswordEncoder : IPasswordHashEncoder<string>
{
    const char SegmentDelimiter = '$';
    const char ParameterDelimiter = ',';
    const char ParameterKvSeparator = '=';
    
    public string Encode(PasswordHashDto hashDto)
    {
        return hashDto.Parameters.Type switch
        {
            PasswordHashType.Argon2Id or PasswordHashType.Argon2I or PasswordHashType.Argon2D =>
                $"{SegmentDelimiter}{hashDto.Parameters.Type.ToString().ToLowerInvariant()}" +
                $"{SegmentDelimiter}v={hashDto.Parameters.Version}" +
                $"{SegmentDelimiter}m={hashDto.Parameters.Memory},t={hashDto.Parameters.Iterations},p={hashDto.Parameters.Parallelism}" +
                (hashDto.KeyId == null ? string.Empty : $",keyid={PhcFormatB64.Encode(hashDto.KeyId)}") +
                (hashDto.AssociatedData == null ? string.Empty : $",data={PhcFormatB64.Encode(hashDto.AssociatedData)}") +
                $"{SegmentDelimiter}{PhcFormatB64.Encode(hashDto.Salt)}" +
                $"{SegmentDelimiter}{PhcFormatB64.Encode(hashDto.Hash)}",
            _ => throw new ArgumentOutOfRangeException()
        };
    }
    
    public PasswordHashDto Decode(string encodedHash)
    {
        PasswordHashType type = default;
        int version = default;
        uint memory = default, iterations = default;
        byte parallelism = default;
        byte[]? keyId = default, associatedData = default;
        byte[] salt = [], hash = [];
        
        ReadOnlySpan<char> chain = encodedHash.AsSpan();
        int chainSegmentIndex = 0;
        for (int i = 0; i < chain.Length;)
        {
            var segment = GetSegment(chain, ref i);
            if (segment.IsEmpty)
            {
                continue;
            }
            
            int segmentIndex = 0;
            switch (chainSegmentIndex++)
            {
                // hash type
                case 0:
                    type = GetHashType(segment);
                    break;
                // version
                case 1:
                    version = GetVersion(segment, ref segmentIndex);
                    break;
                // parameters
                case 2:
                    while (true)
                    {
                        var parameter = GetParameter(segment, ref segmentIndex);
                        if (parameter.IsEmpty)
                        {
                            break;
                        }

                        switch (parameter.Name)
                        {
                            case "m" when !uint.TryParse(parameter.Value, out memory):
                                throw new FormatException($"Invalid 'memory' parameter format. Correct format: 'm{ParameterKvSeparator}1' (limited to uint)");
                            case "t" when !uint.TryParse(parameter.Value, out iterations):
                                throw new FormatException($"Invalid 'iterations' parameter format. Correct format: 't{ParameterKvSeparator}1' (limited to uint)");
                            case "p" when !byte.TryParse(parameter.Value, out parallelism):
                                throw new FormatException($"Invalid 'parallelism' parameter format. Correct format: 'p{ParameterKvSeparator}1' (limited to byte)");
                            case "keyid" when parameter.Value.Length > 11 || !PhcFormatB64.TryDecodeNullable(parameter.Value, out keyId):
                                throw new FormatException("Invalid 'keyid' parameter format." +
                                                          "It should be a Base64 binary representation without padding and a maximum of 8 bytes (11 characters).");
                            case "data" when parameter.Value.Length > 42 || !PhcFormatB64.TryDecodeNullable(parameter.Value, out associatedData):
                                throw new FormatException("Invalid 'data' parameter format." +
                                                          "It should be a Base64 binary representation without padding and a maximum of 32 bytes (42 characters).");
                        }
                    }
                    break;
                // salt
                case 3:
                    if (segment.Length < 11 || segment.Length > 64 || !PhcFormatB64.TryDecode(segment, out salt))
                    {
                        throw new FormatException("Invalid 'salt' format. It should be a Base64 binary representation without padding, a minimum of 8 bytes (11 characters)" +
                                                  "and a maximum of 48 bytes (64 characters).");
                    }
                    break;
                // hash
                case 4:
                    if (segment.Length < 16 || segment.Length > 86 || !PhcFormatB64.TryDecode(segment, out hash))
                    {
                        throw new FormatException("Invalid 'hash' format. It should be a Base64 binary representation without padding, a minimum of 12 bytes (16 characters)" +
                                                  "and a maximum of 64 bytes (86 characters).");
                    }
                    break;
            }
        }

        return new PasswordHashDto(new HashingParameters(type, version, memory, iterations, parallelism), keyId, associatedData, salt, hash);
    }

    private ReadOnlySpan<char> GetSegment(ReadOnlySpan<char> chain, ref int i)
    {
        return GetWithDelimiter(chain, ref i, SegmentDelimiter);
    }
    
    private PhcParameter GetParameter(ReadOnlySpan<char> segment, ref int segmentIndex)
    {
        var parameterSpan = GetWithDelimiter(segment, ref segmentIndex, ParameterDelimiter);
        return new PhcParameter(parameterSpan, ParameterKvSeparator);
    }

    private ReadOnlySpan<char> GetWithDelimiter(ReadOnlySpan<char> span, ref int i, char delimiter)
    {
        var readStartIndex = i;

        var nextSegmentIndex = span[readStartIndex..].IndexOf(delimiter);
        bool thereIsNextSegment = nextSegmentIndex != -1;

        i = thereIsNextSegment ? nextSegmentIndex + i : span.Length;
        var readEndIndex = thereIsNextSegment ? i++ : i;

        var result = span[readStartIndex..readEndIndex];
        return result;
    }

    /// <exception cref="FormatException"></exception>
    private PasswordHashType GetHashType(ReadOnlySpan<char> segment)
    {
        if (!Enum.TryParse(segment, ignoreCase: true, out PasswordHashType type))
        {
            throw new FormatException("Invalid/unhandled hash type found in the encoded string.");
        }
        
        return type;
    }

    /// <exception cref="FormatException"></exception>
    private int GetVersion(ReadOnlySpan<char> segment, ref int segmentIndex)
    {
        var version = 0;
        var parameter = GetParameter(segment, ref segmentIndex);
        if (parameter.IsEmpty || parameter.Name is "v" && !int.TryParse(parameter.Value, out version))
        {
            throw new FormatException($"Invalid 'version' parameter format. Correct format: 'v{ParameterKvSeparator}1' (limited to int)");
        }

        return version;
    }

    /*public PasswordHashDto Decode(string encodedHash)
    {
        var parts = encodedHash.Split('$', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 1)
        {
            throw new FormatException("There wasn't the expected amount of values");
        }

        if (!Enum.TryParse(parts[0], ignoreCase: true, out PasswordHashType hashType))
        {
            throw new FormatException($"'{parts[0]}' is not part of '{nameof(PasswordHashType)}', and hence, is not supported");
        }

        return hashType switch
        {
            PasswordHashType.Argon2Id => DecodeArgon2Id(parts),
            _ => throw new ArgumentOutOfRangeException()
        };
    }

    private PasswordHashDto DecodeArgon2Id(string[] splittedEncoding)
    {
        if (splittedEncoding.Length < 5)
        {
            throw new FormatException("There wasn't the minimum expected amount of values");
        }
        
        var versionParameters = splittedEncoding[1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        int version = int.TryParse(GetParameter(versionParameters, "v"));
        
        return new PasswordHashDto(PasswordHashType.Argon2Id, version, );
    }

    private string GetParameter(string[] parameters, string parameterName)
    {
        foreach (var parameter in parameters)
        {
            if (parameter.StartsWith($"{parameterName}="))
            {
                var lengthParameter = parameterName.Length + 1;
                return parameter[lengthParameter..];
            }
        }

        throw new FormatException($"'{versionParameters[0]}' is not a valid version");
    }*/
}