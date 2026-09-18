using System.Buffers.Binary;

namespace RustRadar.Protocol;

public enum RustWireMessageKind
{
    Other = 0,

    Entities,
    EntityDestroy,
    RpcMessage,
    EntityPosition,
    Effect,
    EntityFlags
}

public enum RustPositionShape
{
    None = 0,

    Position36,
    Position44,

    Unexpected
}

public enum ProtectionCounterStatus
{
    None = 0,

    First,
    InOrder,
    Gap,
    Duplicate,
    OutOfOrder
}

/*
 * Observed protection-envelope states.
 *
 * IMPORTANT:
 *
 * These names describe only the literal bytes
 * seen on the wire.
 *
 * We are NOT assigning cryptographic semantics
 * such as "old key", "new key", "server key",
 * etc. until we have evidence for that.
 */
public enum RustProtectionState
{
    None = 0,

    State0100,
    State0101,

    Unknown
}

public readonly record struct CounterTrackerResult(
    ProtectionCounterStatus Status,
    long? Delta);

public sealed record RustWireMessageInfo(
    DateTime TimestampUtc,
    string Direction,

    byte RawType,
    RustWireMessageKind Kind,
    string Name,

    int PacketLength,

    bool IsProtected,

    /*
     * When protected:
     *
     * This is the opaque/protected body only.
     *
     * It excludes:
     *
     * type byte
     * uint32 counter
     * 2-byte protection state
     * 16-byte authentication/tag trailer
     */
    byte[] ProtectedBody,

    /*
     * Used only for packets without the
     * protection envelope.
     */
    byte[] PlainBody,

    uint? Counter,

    /*
     * Raw little-endian representation of
     * the two protection-state bytes.
     *
     * Wire:
     *
     * 01 00 -> ushort 0x0001
     * 01 01 -> ushort 0x0101
     */
    ushort? ProtectionFlags,

    byte[] AuthenticationTag,

    RustPositionShape PositionShape,

    ProtectionCounterStatus CounterStatus,

    long? CounterDelta)
{
    public int ProtectedBodyLength =>
        ProtectedBody.Length;

    public int BodyLength =>
        IsProtected
            ? ProtectedBody.Length
            : PlainBody.Length;

    /*
     * Literal protection-envelope state.
     */
    public RustProtectionState ProtectionState =>
        ProtectionFlags switch
        {
            0x0001 =>
                RustProtectionState.State0100,

            0x0101 =>
                RustProtectionState.State0101,

            null =>
                RustProtectionState.None,

            _ =>
                RustProtectionState.Unknown
        };

    /*
     * Expose the actual two bytes independently.
     *
     * This avoids baking assumptions about what
     * each byte means into the parser.
     */
    public byte? ProtectionStateByte0
    {
        get
        {
            if (!ProtectionFlags.HasValue)
                return null;

            return (byte)(
                ProtectionFlags.Value &
                0x00FF);
        }
    }

    public byte? ProtectionStateByte1
    {
        get
        {
            if (!ProtectionFlags.HasValue)
                return null;

            return (byte)(
                (
                    ProtectionFlags.Value >>
                    8) &
                0x00FF);
        }
    }

    public string ProtectionStateText =>
        ProtectionState switch
        {
            RustProtectionState.State0100 =>
                "0100",

            RustProtectionState.State0101 =>
                "0101",

            RustProtectionState.None =>
                "",

            _ =>
                ProtectionFlags.HasValue
                    ? $"{ProtectionStateByte0:X2}" +
                      $"{ProtectionStateByte1:X2}"
                    : ""
        };

    /*
     * Kept for compatibility with the existing
     * MainWindow / logging code.
     */
    public string BodyPreviewHex
    {
        get
        {
            byte[] data =
                IsProtected
                    ? ProtectedBody
                    : PlainBody;

            if (data.Length == 0)
                return "";

            int count =
                Math.Min(
                    data.Length,
                    32);

            return Convert.ToHexString(
                data.AsSpan(
                    0,
                    count));
        }
    }

    public string AuthenticationTagHex =>
        AuthenticationTag.Length > 0
            ? Convert.ToHexString(
                AuthenticationTag)
            : "";
}

public static class RustWireMessageParser
{
    /*
     * RakNet's user-packet range used by this
     * Rust protocol starts above the internal
     * RakNet message range.
     */
    private const byte MinimumRustPacketType =
        0x8D;

    /*
     * Protection trailer:
     *
     * uint32 counter
     * byte state0
     * byte state1
     * byte[16] tag
     *
     * Total = 22 bytes.
     */
    private const int ProtectionTrailerLength =
        22;

    private const int AuthenticationTagLength =
        16;

    public static RustWireMessageInfo? Parse(
        ReadOnlySpan<byte> packet,
        DateTime timestampUtc,
        string direction)
    {
        if (packet.Length == 0)
            return null;

        byte rawType =
            packet[0];

        /*
         * Do not feed RakNet's own low-numbered
         * control payloads into the Rust inspector.
         */
        if (rawType <
            MinimumRustPacketType)
        {
            return null;
        }

        RustWireMessageKind kind =
            GetKind(
                rawType);

        string name =
            GetName(
                rawType,
                kind);

        ReadOnlySpan<byte> body =
            packet[1..];

        bool protectedPacket =
            TryParseProtectionEnvelope(
                body,

                out byte[] protectedBody,

                out uint counter,

                out ushort flags,

                out byte[] authTag);

        byte[] plainBody;

        uint? parsedCounter;
        ushort? parsedFlags;

        if (protectedPacket)
        {
            plainBody =
                Array.Empty<byte>();

            parsedCounter =
                counter;

            parsedFlags =
                flags;
        }
        else
        {
            protectedBody =
                Array.Empty<byte>();

            authTag =
                Array.Empty<byte>();

            plainBody =
                body.ToArray();

            parsedCounter =
                null;

            parsedFlags =
                null;
        }

        RustPositionShape positionShape =
            DeterminePositionShape(
                rawType,
                protectedPacket,
                protectedBody,
                plainBody);

        return new RustWireMessageInfo(
            timestampUtc,
            direction,

            rawType,
            kind,
            name,

            packet.Length,

            protectedPacket,

            protectedBody,
            plainBody,

            parsedCounter,
            parsedFlags,

            authTag,

            positionShape,

            ProtectionCounterStatus.None,
            null);
    }

    private static RustWireMessageKind GetKind(
        byte rawType)
    {
        return rawType switch
        {
            0x91 =>
                RustWireMessageKind.Entities,

            0x92 =>
                RustWireMessageKind.EntityDestroy,

            0x95 =>
                RustWireMessageKind.RpcMessage,

            0x96 =>
                RustWireMessageKind.EntityPosition,

            0x99 =>
                RustWireMessageKind.Effect,

            0xA3 =>
                RustWireMessageKind.EntityFlags,

            _ =>
                RustWireMessageKind.Other
        };
    }

    private static string GetName(
        byte rawType,
        RustWireMessageKind kind)
    {
        /*
         * Only give semantic names to message IDs
         * whose meaning we actually know.
         */
        return kind switch
        {
            RustWireMessageKind.Entities =>
                "Entities",

            RustWireMessageKind.EntityDestroy =>
                "EntityDestroy",

            RustWireMessageKind.RpcMessage =>
                "RPCMessage",

            RustWireMessageKind.EntityPosition =>
                "EntityPosition",

            RustWireMessageKind.Effect =>
                "Effect",

            RustWireMessageKind.EntityFlags =>
                "EntityFlags",

            _ =>
                $"Message{rawType:X2}"
        };
    }

    private static RustPositionShape
        DeterminePositionShape(
            byte rawType,
            bool protectedPacket,
            byte[] protectedBody,
            byte[] plainBody)
    {
        if (rawType != 0x96)
        {
            return RustPositionShape.None;
        }

        int length =
            protectedPacket
                ? protectedBody.Length
                : plainBody.Length;

        return length switch
        {
            36 =>
                RustPositionShape.Position36,

            44 =>
                RustPositionShape.Position44,

            _ =>
                RustPositionShape.Unexpected
        };
    }

    private static bool TryParseProtectionEnvelope(
        ReadOnlySpan<byte> body,

        out byte[] protectedBody,
        out uint counter,
        out ushort flags,
        out byte[] authTag)
    {
        protectedBody =
            Array.Empty<byte>();

        authTag =
            Array.Empty<byte>();

        counter =
            0;

        flags =
            0;

        /*
         * Observed envelope:
         *
         * [opaque/protected body]
         * [uint32 little-endian counter]
         * [01 00 OR 01 01]
         * [16-byte trailer/tag]
         *
         * Trailer total:
         *
         * 4 + 2 + 16 = 22 bytes
         */
        if (body.Length <
            ProtectionTrailerLength)
        {
            return false;
        }

        int metadataOffset =
            body.Length -
            ProtectionTrailerLength;

        /*
         * Metadata layout:
         *
         * +0 uint32 counter
         * +4 state byte 0
         * +5 state byte 1
         */
        ReadOnlySpan<byte> metadata =
            body.Slice(
                metadataOffset,
                6);

        byte state0 =
            metadata[4];

        byte state1 =
            metadata[5];

        /*
         * Confirmed states from our captures:
         *
         * 01 00
         * 01 01
         *
         * Do NOT broaden this detector to arbitrary
         * 01 XX values yet. Doing so would increase
         * false positives on genuine plaintext.
         */
        bool knownProtectionState =
            state0 == 0x01 &&
            (
                state1 == 0x00 ||
                state1 == 0x01
            );

        if (!knownProtectionState)
        {
            return false;
        }

        counter =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    metadata[..4]);

        flags =
            BinaryPrimitives
                .ReadUInt16LittleEndian(
                    metadata.Slice(
                        4,
                        2));

        protectedBody =
            body[..metadataOffset]
                .ToArray();

        authTag =
            body.Slice(
                    metadataOffset + 6,
                    AuthenticationTagLength)
                .ToArray();

        return true;
    }
}

/*
 * Tracks protection counters independently for:
 *
 * direction + protection state
 *
 * This is important because our captures show
 * that a transition such as:
 *
 * S2C 01 00 counter 2514
 *
 * followed by:
 *
 * S2C 01 01 counter 1
 *
 * is NOT an out-of-order packet.
 *
 * It is a different protection-state stream
 * whose counter starts separately.
 */
public sealed class ProtectionCounterTracker
{
    private readonly object
        _sync =
            new();

    private readonly Dictionary<
        string,
        uint> _lastByStream =
            new(
                StringComparer.OrdinalIgnoreCase);

    /*
     * Compatibility overload.
     *
     * Existing callers can still compile, although
     * PacketCaptureService should use the overload
     * that also passes ProtectionFlags.
     */
    public CounterTrackerResult Observe(
        string direction,
        uint? counter)
    {
        return Observe(
            direction,
            counter,
            null);
    }

    public CounterTrackerResult Observe(
        string direction,
        uint? counter,
        ushort? protectionFlags)
    {
        if (!counter.HasValue)
        {
            return new CounterTrackerResult(
                ProtectionCounterStatus.None,
                null);
        }

        string streamKey =
            BuildStreamKey(
                direction,
                protectionFlags);

        lock (_sync)
        {
            uint current =
                counter.Value;

            if (!_lastByStream.TryGetValue(
                    streamKey,
                    out uint last))
            {
                _lastByStream[
                    streamKey] =
                        current;

                return new CounterTrackerResult(
                    ProtectionCounterStatus.First,
                    null);
            }

            if (current ==
                last)
            {
                return new CounterTrackerResult(
                    ProtectionCounterStatus.Duplicate,
                    0);
            }

            /*
             * uint subtraction naturally handles
             * 32-bit wraparound.
             */
            uint forward =
                unchecked(
                    current -
                    last);

            /*
             * If current is logically ahead of last,
             * the unsigned forward difference will be
             * less than half the uint range.
             */
            if (forward <
                0x80000000u)
            {
                _lastByStream[
                    streamKey] =
                        current;

                if (forward ==
                    1)
                {
                    return new CounterTrackerResult(
                        ProtectionCounterStatus.InOrder,
                        1);
                }

                return new CounterTrackerResult(
                    ProtectionCounterStatus.Gap,
                    forward);
            }

            /*
             * Packet arrived behind the newest counter
             * we've already seen for THIS direction
             * and protection state.
             */
            uint backwards =
                unchecked(
                    last -
                    current);

            return new CounterTrackerResult(
                ProtectionCounterStatus.OutOfOrder,
                -(long)backwards);
        }
    }

    private static string BuildStreamKey(
        string direction,
        ushort? protectionFlags)
    {
        /*
         * Examples:
         *
         * S2C:0001 -> wire state 01 00
         * S2C:0101 -> wire state 01 01
         * C2S:0101 -> wire state 01 01
         *
         * NONE exists only for compatibility if
         * the older overload is used.
         */
        string state =
            protectionFlags.HasValue
                ? protectionFlags.Value.ToString(
                    "X4")
                : "NONE";

        return $"{direction}:{state}";
    }

    public void Reset()
    {
        lock (_sync)
        {
            _lastByStream.Clear();
        }
    }
}