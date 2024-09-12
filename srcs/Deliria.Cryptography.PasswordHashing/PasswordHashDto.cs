using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;

namespace Deliria.Cryptography.PasswordHashing;

/** Based on https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md */
[DataContract]
public sealed record PasswordHashDto(
    [property: DataMember(Order = 0)] HashingParameters Parameters,
    [property: DataMember(Order = 1)][property: MaxLength(8)] byte[]? KeyId,
    [property: DataMember(Order = 2)][property: MaxLength(32)] byte[]? AssociatedData,
    [property: DataMember(Order = 3)][property: MinLength(8)][property: MaxLength(48)] byte[] Salt,
    [property: DataMember(Order = 4)][property: MinLength(12)][property: MaxLength(64)] byte[] Hash)
{
    public bool Equals(PasswordHashDto? other)
    {
        return other != null
               && Parameters.Equals(other.Parameters)
               && (KeyId == other.KeyId || KeyId != null && other.KeyId != null && KeyId.SequenceEqual(other.KeyId))
               && (AssociatedData == other.AssociatedData || AssociatedData != null && other.AssociatedData != null && AssociatedData.SequenceEqual(other.AssociatedData))
               && Salt.SequenceEqual(other.Salt)
               && Hash.SequenceEqual(other.Hash);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(Parameters, KeyId, AssociatedData, Salt, Hash);
    }
}