namespace Deliria.Cryptography.PasswordHashing;

public static class PhcFormatB64
{
    public static string Encode(ReadOnlySpan<byte> array)
    {
        return Convert.ToBase64String(array).TrimEnd('=');
    }
    
    public static byte[] DecodeAsBytes(string text)
    {
        int padding = 4 - text.Length % 4;
        if (padding < 4)
        {
            text = text.PadRight(text.Length + padding, '=');
        }
        return Convert.FromBase64String(text);
    }
    
    public static ReadOnlySpan<byte> DecodeAsSpan(string text)
    {
        return DecodeAsBytes(text);
    }

    public static bool TryDecodeNullable(ReadOnlySpan<char> text, out byte[]? result)
    {
        try
        {
            // TODO: see if we can avoid allocating this string
            result = DecodeAsBytes(text.ToString());
            return true;
        }
        catch
        {
            // ignored
        }
        
        result = null;
        return false;
    }
    
    public static bool TryDecode(ReadOnlySpan<char> text, out byte[] result)
    {
        try
        {
            // TODO: see if we can avoid allocating this string
            result = DecodeAsBytes(text.ToString());
            return true;
        }
        catch
        {
            // ignored
        }
        
        result = [];
        return false;
    }

    public static bool TryDecode(ReadOnlySpan<char> text, out ReadOnlySpan<byte> result)
    {
        try
        {
            // TODO: see if we can avoid allocating this string
            result = DecodeAsSpan(text.ToString());
            return true;
        }
        catch
        {
            // ignored
        }
        
        result = ReadOnlySpan<byte>.Empty;
        return false;
    }
}