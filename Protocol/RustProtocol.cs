using System.Buffers.Binary;

namespace RustRadar.Protocol;

public enum RustMessageType : byte
{
    Entities = 5,
    EntityDestroy = 6,

    RpcMessage = 9,
    EntityPosition = 10,

    ConsoleMessage = 11,
    ConsoleCommand = 12,

    Effect = 13,

    // Observed as raw 0xA3 in our capture.
    // 0xA3 - 140 = 23.
    EntityFlags = 23
}

public sealed record RustPosition(
    ulong EntityId,
    float X,
    float Y,
    float Z,
    float RotationX,
    float RotationY,
    float RotationZ,
    float Time,
    ulong? ParentId);

public sealed class RustMessageInfo
{
    public byte RawType { get; init; }

    public int TypeId { get; init; }

    public RustMessageType? KnownType { get; init; }

    public string Name { get; init; } = "Unknown";

    /// <summary>
    /// Total application packet length, including the first Rust type byte.
    /// </summary>
    public int PacketLength { get; init; }

    /// <summary>
    /// True when this looks like the 22-byte protection envelope
    /// observed in the live Rust traffic:
    ///
    /// [ciphertext][6 byte metadata][16 byte tag]
    /// </summary>
    public bool IsProtected { get; init; }

    /// <summary>
    /// Length of protected ciphertext, excluding type byte,
    /// six-byte metadata and sixteen-byte tag.
    /// </summary>
    public int CiphertextLength { get; init; }

    /// <summary>
    /// First four bytes of the observed six-byte trailer metadata.
    /// Appears to increment globally.
    /// </summary>
    public uint? ProtectionCounter { get; init; }

    /// <summary>
    /// Last two bytes of the six-byte metadata block.
    /// In our capture this has been 0x0101.
    /// </summary>
    public ushort? ProtectionFlags { get; init; }

    /// <summary>
    /// Populated only if EntityPosition is actually plaintext.
    /// </summary>
    public RustPosition? Position { get; init; }

    /// <summary>
    /// Populated for a plaintext EntityDestroy.
    /// </summary>
    public ulong? DestroyedEntityId { get; init; }
}

public static class RustProtocolParser
{
    public const byte RakNetMaximumType = 140;

    public static RustMessageInfo? Parse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length == 0)
            return null;

        byte rawType = packet[0];

        // Facepunch application packet types begin above 140.
        if (rawType <= RakNetMaximumType)
            return null;

        int typeId = rawType - RakNetMaximumType;

        RustMessageType? knownType = typeId switch
        {
            5 => RustMessageType.Entities,
            6 => RustMessageType.EntityDestroy,
            9 => RustMessageType.RpcMessage,
            10 => RustMessageType.EntityPosition,
            11 => RustMessageType.ConsoleMessage,
            12 => RustMessageType.ConsoleCommand,
            13 => RustMessageType.Effect,
            23 => RustMessageType.EntityFlags,
            _ => null
        };

        string name = knownType?.ToString() ?? $"Message{typeId}";

        if (knownType == RustMessageType.EntityPosition)
        {
            if (packet.Length != 37 &&
                packet.Length != 45 &&
                packet.Length != 59 &&
                packet.Length != 67)
            {
                knownType = null;
            }
        }

        if (knownType == RustMessageType.EntityDestroy)
        {
            if (packet.Length != 10 &&
                packet.Length != 32)
            {
                knownType = null;
            }
        }

        ReadOnlySpan<byte> body = packet[1..];

        bool protectedPacket = LooksLikeProtectedBody(body);

        uint? protectionCounter = null;
        ushort? protectionFlags = null;
        int ciphertextLength = 0;

        if (protectedPacket)
        {
            ReadOnlySpan<byte> metadata =
                body.Slice(body.Length - 22, 6);

            protectionCounter =
                BinaryPrimitives.ReadUInt32LittleEndian(metadata[..4]);

            protectionFlags =
                BinaryPrimitives.ReadUInt16LittleEndian(metadata[4..6]);

            ciphertextLength = body.Length - 22;
        }

        RustPosition? position = null;
        ulong? destroyedEntity = null;

        // Parse a position only if it is NOT protected.
        if (!protectedPacket &&
            knownType == RustMessageType.EntityPosition)
        {
            position = TryParsePosition(body);
        }

        if (!protectedPacket &&
            knownType == RustMessageType.EntityDestroy &&
            body.Length >= 9)
        {
            destroyedEntity =
                BinaryPrimitives.ReadUInt64LittleEndian(body[..8]);
        }

        return new RustMessageInfo
        {
            RawType = rawType,
            TypeId = typeId,
            KnownType = knownType,
            Name = name,

            PacketLength = packet.Length,

            IsProtected = protectedPacket,
            CiphertextLength = ciphertextLength,

            ProtectionCounter = protectionCounter,
            ProtectionFlags = protectionFlags,

            Position = position,
            DestroyedEntityId = destroyedEntity
        };
    }

    private static bool LooksLikeProtectedBody(
        ReadOnlySpan<byte> body)
    {
        /*
         * Observed live layout:
         *
         * [ciphertext]
         * [counter / metadata: 6 bytes]
         * [auth tag: 16 bytes]
         *
         * Total overhead = 22 bytes.
         *
         * Our captures have:
         *
         * metadata[4] == 0x01
         * metadata[5] == 0x01
         */

        if (body.Length < 22)
            return false;

        int metadataOffset = body.Length - 22;

        ReadOnlySpan<byte> metadata =
            body.Slice(metadataOffset, 6);

        return metadata[4] == 0x01 &&
               metadata[5] == 0x01;
    }

    private static RustPosition? TryParsePosition(
        ReadOnlySpan<byte> body)
    {
        /*
         * Facepunch:
         *
         * ulong entityId        8
         *
         * float x               4
         * float y               4
         * float z               4
         *
         * float rotX            4
         * float rotY            4
         * float rotZ            4
         *
         * float time            4
         *
         * optional ulong parent 8
         *
         * Minimum body = 36 bytes
         */

        if (body.Length < 36)
            return null;

        ulong entityId =
            BinaryPrimitives.ReadUInt64LittleEndian(
                body[..8]);

        float x =
            BinaryPrimitives.ReadSingleLittleEndian(
                body.Slice(8, 4));

        float y =
            BinaryPrimitives.ReadSingleLittleEndian(
                body.Slice(12, 4));

        float z =
            BinaryPrimitives.ReadSingleLittleEndian(
                body.Slice(16, 4));

        float rotX =
            BinaryPrimitives.ReadSingleLittleEndian(
                body.Slice(20, 4));

        float rotY =
            BinaryPrimitives.ReadSingleLittleEndian(
                body.Slice(24, 4));

        float rotZ =
            BinaryPrimitives.ReadSingleLittleEndian(
                body.Slice(28, 4));

        float time =
            BinaryPrimitives.ReadSingleLittleEndian(
                body.Slice(32, 4));

        ulong? parent = null;

        if (body.Length >= 44)
        {
            parent =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    body.Slice(36, 8));
        }

        return new RustPosition(
            entityId,
            x,
            y,
            z,
            rotX,
            rotY,
            rotZ,
            time,
            parent);
    }
}