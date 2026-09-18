using System.Buffers.Binary;

namespace RustRadar.Protocol;

public sealed record RustEntityPosition(
    DateTime TimestampUtc,
    string Direction,

    ulong EntityId,

    float X,
    float Y,
    float Z,

    float RotationX,
    float RotationY,
    float RotationZ,

    float NetworkTime,

    ulong? ParentId,

    bool WasProtected,
    RustProtectionState ProtectionState);

public static class RustEntityPositionParser
{
    public static bool TryParse(
        RustWireMessageInfo message,
        out RustEntityPosition? position)
    {
        position =
            null;

        if (message.Kind !=
            RustWireMessageKind.EntityPosition)
        {
            return false;
        }

        /*
         * EffectiveBody is:
         *
         * - decrypted body, if decryption succeeded
         * - plaintext body, for encryption=0
         * - empty, for opaque 01 01
         */
        byte[] body =
            message.EffectiveBody;

        if (body.Length != 36 &&
            body.Length != 44)
        {
            return false;
        }

        ReadOnlySpan<byte> span =
            body;

        ulong entityId =
            BinaryPrimitives
                .ReadUInt64LittleEndian(
                    span[..8]);

        float x =
            BinaryPrimitives
                .ReadSingleLittleEndian(
                    span.Slice(8, 4));

        float y =
            BinaryPrimitives
                .ReadSingleLittleEndian(
                    span.Slice(12, 4));

        float z =
            BinaryPrimitives
                .ReadSingleLittleEndian(
                    span.Slice(16, 4));

        float rotationX =
            BinaryPrimitives
                .ReadSingleLittleEndian(
                    span.Slice(20, 4));

        float rotationY =
            BinaryPrimitives
                .ReadSingleLittleEndian(
                    span.Slice(24, 4));

        float rotationZ =
            BinaryPrimitives
                .ReadSingleLittleEndian(
                    span.Slice(28, 4));

        float networkTime =
            BinaryPrimitives
                .ReadSingleLittleEndian(
                    span.Slice(32, 4));

        ulong? parentId =
            null;

        if (body.Length == 44)
        {
            parentId =
                BinaryPrimitives
                    .ReadUInt64LittleEndian(
                        span.Slice(36, 8));
        }

        position =
            new RustEntityPosition(
                message.TimestampUtc,
                message.Direction,

                entityId,

                x,
                y,
                z,

                rotationX,
                rotationY,
                rotationZ,

                networkTime,

                parentId,

                message.IsProtected,
                message.ProtectionState);

        return true;
    }
}