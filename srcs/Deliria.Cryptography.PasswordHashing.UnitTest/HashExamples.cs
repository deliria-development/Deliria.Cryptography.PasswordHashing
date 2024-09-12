namespace Deliria.Cryptography.PasswordHashing.UnitTest;

public static class HashExamples
{
    public static readonly HashExample[] Argon = [
        new(new InputParams("ojnfgsduinligfjkbuywebtirlg".ToBytes()), new ExtraDataParams(PhcFormatB64.DecodeAsBytes("ZW8yd3hYTkpLUEMzaFhRVg")),
            new PasswordHashDto(new HashingParameters(PasswordHashType.Argon2Id, 0x13, 7*1024, 5, 1), null, null,
                PhcFormatB64.DecodeAsBytes("ZW8yd3hYTkpLUEMzaFhRVg"),
                PhcFormatB64.DecodeAsBytes("u5xwp6NoJFfgdiciG7OjkABU9WF7WfcP3CiutAZW364n4moX+waEBkkwkwOC4ABxqR8LVfIj3lQjS73uSgFS0A")),
            "$argon2id$v=19$m=7168,t=5,p=1$ZW8yd3hYTkpLUEMzaFhRVg$u5xwp6NoJFfgdiciG7OjkABU9WF7WfcP3CiutAZW364n4moX+waEBkkwkwOC4ABxqR8LVfIj3lQjS73uSgFS0A"),
        new(new InputParams("120superMega-ultraTest#@~\u20ac\u00ac\u20ac\u00ac98".ToBytes()), new ExtraDataParams(PhcFormatB64.DecodeAsBytes("TnhNWjhaRGk3YkVOZUtjNg")),
            new PasswordHashDto(new HashingParameters(PasswordHashType.Argon2Id, 0x13, 7*1024, 5, 1),
                PhcFormatB64.DecodeAsBytes("cGl6emE"), null,
                PhcFormatB64.DecodeAsBytes("TnhNWjhaRGk3YkVOZUtjNg"),
                PhcFormatB64.DecodeAsBytes("stcA+MuSQX8uERuYvxY+nWUd8/k7ijMpOAITt79L4oqPpL4RAl8UnUbqaF1L6Kw1nckd+sapvVF+lr7QF+vPeQ")),
            "$argon2id$v=19$m=7168,t=5,p=1,keyid=cGl6emE$TnhNWjhaRGk3YkVOZUtjNg$stcA+MuSQX8uERuYvxY+nWUd8/k7ijMpOAITt79L4oqPpL4RAl8UnUbqaF1L6Kw1nckd+sapvVF+lr7QF+vPeQ"),
    ];
}