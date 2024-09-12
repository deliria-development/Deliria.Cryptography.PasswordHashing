using System.Runtime.Serialization;

namespace Deliria.Cryptography.PasswordHashing;

[DataContract]
public record HashingParameters(
    [property: DataMember(Order = 0)] PasswordHashType Type,
    [property: DataMember(Order = 1)] int Version,
    [property: DataMember(Order = 2)] uint Memory,
    [property: DataMember(Order = 3)] uint Iterations,
    [property: DataMember(Order = 4)] byte Parallelism);