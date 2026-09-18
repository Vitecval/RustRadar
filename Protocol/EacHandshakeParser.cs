using System.Buffers.Binary;
using System.IO;

namespace RustRadar.Protocol;

public enum EacTransportOpcode : ushort
{
    FragmentMiddle = 0,
    FragmentStart = 1,
    FragmentEnd = 2,
    Single = 3,
    AckLike = 7,

    Control11 = 11,
    Control19 = 19,
    Control35 = 35,
    Control71 = 71
}

public sealed record EacTransportFrame(
    uint DeclaredLength,
    ushort ProtocolVersion,
    ushort Opcode,
    ulong SessionId,
    ulong Sequence,
    uint Token,
    byte[] Payload)
{
    public string OpcodeName =>
        Opcode switch
        {
            0 => "FragmentMiddle",
            1 => "FragmentStart",
            2 => "FragmentEnd",
            3 => "Single",
            7 => "AckLike",
            11 => "Control11",
            19 => "Control19",
            35 => "Control35",
            71 => "Control71",
            _ => $"Unknown{Opcode}"
        };
}

public sealed record EacLogicalMessage(
    DateTime TimestampUtc,
    string Direction,
    ulong SessionId,

    byte[] Data,

    uint DeclaredLength,
    uint HeaderVersion,
    uint MessageId,
    uint ProtocolFamily,
    uint MessageType,
    uint Stage,
    uint? Step)
{
    public bool LengthMatches =>
        DeclaredLength ==
        Data.Length;

    public string PreviewHex
    {
        get
        {
            int count =
                Math.Min(
                    Data.Length,
                    96);

            return Convert.ToHexString(
                Data.AsSpan(
                    0,
                    count));
        }
    }

    public string MessageTypeHex =>
        $"0x{MessageType:X2}";
}

public static class EacHandshakeParser
{
    /*
     * Rust raw application type:
     *
     * 0xA2 - 140 = message type 22
     *
     * Current observations identify this as the
     * EAC / NetProtect handshake transport.
     */
    public const byte RustMessageType =
        0xA2;

    /*
     * Observed EAC transport header:
     *
     * 00 uint32 DeclaredLength
     * 04 uint16 ProtocolVersion
     * 06 uint16 Opcode
     * 08 uint64 SessionId
     * 10 uint64 Sequence
     * 18 uint32 Token
     * 1C byte[] Payload
     */
    public const int TransportHeaderSize =
        28;

    public static bool TryParseTransport(
        ReadOnlySpan<byte> body,
        out EacTransportFrame? frame)
    {
        frame =
            null;

        if (body.Length <
            TransportHeaderSize)
        {
            return false;
        }

        uint declaredLength =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    body.Slice(
                        0,
                        4));

        /*
         * Every valid frame observed so far:
         *
         * DeclaredLength = entire body minus
         * the four-byte length field itself.
         */
        if (declaredLength !=
            body.Length - 4)
        {
            return false;
        }

        ushort protocolVersion =
            BinaryPrimitives
                .ReadUInt16LittleEndian(
                    body.Slice(
                        4,
                        2));

        ushort opcode =
            BinaryPrimitives
                .ReadUInt16LittleEndian(
                    body.Slice(
                        6,
                        2));

        ulong sessionId =
            BinaryPrimitives
                .ReadUInt64LittleEndian(
                    body.Slice(
                        8,
                        8));

        ulong sequence =
            BinaryPrimitives
                .ReadUInt64LittleEndian(
                    body.Slice(
                        16,
                        8));

        uint token =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    body.Slice(
                        24,
                        4));

        byte[] transportPayload =
            body.Slice(
                    TransportHeaderSize)
                .ToArray();

        frame =
            new EacTransportFrame(
                declaredLength,
                protocolVersion,
                opcode,
                sessionId,
                sequence,
                token,
                transportPayload);

        return true;
    }

    /*
     * Reassembled logical EAC messages currently
     * appear to start with:
     *
     * 00 uint32 totalLength
     * 04 uint32 headerVersion
     * 08 uint32 messageId
     * 0C uint32 protocolFamily
     * 10 uint32 messageType
     * 14 uint32 stage
     * 18 uint32 step        (when present)
     *
     * The exact semantics of several fields are
     * still observational names rather than
     * confirmed Epic field names.
     */
    public static bool TryParseLogical(
        DateTime timestampUtc,
        string direction,
        ulong sessionId,
        ReadOnlySpan<byte> data,
        out EacLogicalMessage? message)
    {
        message =
            null;

        if (data.Length < 24)
        {
            return false;
        }

        uint declaredLength =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    data.Slice(
                        0,
                        4));

        /*
         * This is a useful sanity check.
         *
         * Don't reject mismatches yet because
         * we're researching the format and don't
         * want a slightly different subtype to
         * disappear from the logs.
         */
        uint headerVersion =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    data.Slice(
                        4,
                        4));

        uint messageId =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    data.Slice(
                        8,
                        4));

        uint protocolFamily =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    data.Slice(
                        12,
                        4));

        uint messageType =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    data.Slice(
                        16,
                        4));

        uint stage =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    data.Slice(
                        20,
                        4));

        uint? step =
            null;

        if (data.Length >= 28)
        {
            step =
                BinaryPrimitives
                    .ReadUInt32LittleEndian(
                        data.Slice(
                            24,
                            4));
        }

        message =
            new EacLogicalMessage(
                timestampUtc,
                direction,
                sessionId,
                data.ToArray(),
                declaredLength,
                headerVersion,
                messageId,
                protocolFamily,
                messageType,
                stage,
                step);

        return true;
    }
}

public sealed class EacMessageAssembler
{
    private sealed class FragmentState
    {
        public ulong SessionId;

        public ulong StartSequence;

        public ulong? EndSequence;

        public uint ExpectedLength;

        public readonly SortedDictionary<
            ulong,
            byte[]> Pieces =
                new();
    }

    /*
     * C2S and S2C can both be assembling at the
     * same time, so keep separate state.
     */
    private readonly Dictionary<
        string,
        FragmentState> _states =
            new(
                StringComparer.OrdinalIgnoreCase);

    public void Clear()
    {
        _states.Clear();
    }

    public EacLogicalMessage? Process(
        DateTime timestampUtc,
        string direction,
        EacTransportFrame frame)
    {
        switch (frame.Opcode)
        {
            /*
             * Complete logical EAC message in
             * one transport frame.
             */
            case (ushort)EacTransportOpcode.Single:

                return ParseComplete(
                    timestampUtc,
                    direction,
                    frame.SessionId,
                    frame.Payload);


            /*
             * Beginning of fragmented message.
             *
             * The first bytes of Payload are also
             * the logical message's own uint32
             * totalLength field.
             */
            case (ushort)EacTransportOpcode.FragmentStart:

                return BeginFragmentedMessage(
                    direction,
                    frame);


            case (ushort)EacTransportOpcode.FragmentMiddle:

                return ContinueFragmentedMessage(
                    timestampUtc,
                    direction,
                    frame,
                    isFinal:
                        false);


            case (ushort)EacTransportOpcode.FragmentEnd:

                return ContinueFragmentedMessage(
                    timestampUtc,
                    direction,
                    frame,
                    isFinal:
                        true);


            /*
             * Controls / ACKs contain no logical
             * application message for us to parse.
             */
            default:

                return null;
        }
    }

    private EacLogicalMessage?
        BeginFragmentedMessage(
            string direction,
            EacTransportFrame frame)
    {
        if (frame.Payload.Length < 4)
        {
            return null;
        }

        uint expectedLength =
            BinaryPrimitives
                .ReadUInt32LittleEndian(
                    frame.Payload
                        .AsSpan(
                            0,
                            4));

        /*
         * Guard against obviously bogus length
         * values while still allowing large EAC
         * blobs.
         */
        if (expectedLength < 4 ||
            expectedLength >
            16 * 1024 * 1024)
        {
            return null;
        }

        FragmentState state =
            new()
            {
                SessionId =
                    frame.SessionId,

                StartSequence =
                    frame.Sequence,

                ExpectedLength =
                    expectedLength
            };

        state.Pieces[
            frame.Sequence] =
                frame.Payload;

        _states[
            direction] =
                state;

        return null;
    }

    private EacLogicalMessage?
        ContinueFragmentedMessage(
            DateTime timestampUtc,
            string direction,
            EacTransportFrame frame,
            bool isFinal)
    {
        if (!_states.TryGetValue(
                direction,
                out FragmentState? state))
        {
            return null;
        }

        /*
         * A different session appeared while an
         * old message was incomplete.
         *
         * Drop stale state rather than combining
         * two sessions.
         */
        if (state.SessionId !=
            frame.SessionId)
        {
            _states.Remove(
                direction);

            return null;
        }

        state.Pieces[
            frame.Sequence] =
                frame.Payload;

        if (isFinal)
        {
            state.EndSequence =
                frame.Sequence;
        }

        if (!state.EndSequence.HasValue)
        {
            return null;
        }

        ulong endSequence =
            state.EndSequence.Value;

        if (endSequence <
            state.StartSequence)
        {
            _states.Remove(
                direction);

            return null;
        }

        /*
         * Don't assemble until every fragment
         * between start and end has arrived.
         */
        for (ulong sequence =
                 state.StartSequence;
             sequence <= endSequence;
             sequence++)
        {
            if (!state.Pieces
                    .ContainsKey(
                        sequence))
            {
                return null;
            }

            /*
             * Prevent ulong overflow in an
             * extremely malformed packet.
             */
            if (sequence ==
                ulong.MaxValue)
            {
                break;
            }
        }

        using MemoryStream stream =
            new();

        for (ulong sequence =
                 state.StartSequence;
             sequence <= endSequence;
             sequence++)
        {
            byte[] piece =
                state.Pieces[
                    sequence];

            stream.Write(
                piece,
                0,
                piece.Length);

            if (sequence ==
                ulong.MaxValue)
            {
                break;
            }
        }

        byte[] complete =
            stream.ToArray();

        /*
         * All captures so far match exactly:
         *
         * S2C:
         * 488 + 24 = 512
         *
         * C2S:
         * 488 + 488 + 488 + 164 = 1628
         */
        if (complete.Length !=
            state.ExpectedLength)
        {
            /*
             * Final fragment arrived but sizes
             * don't agree.
             *
             * Remove it so a corrupt state doesn't
             * poison following handshake messages.
             */
            _states.Remove(
                direction);

            return null;
        }

        _states.Remove(
            direction);

        return ParseComplete(
            timestampUtc,
            direction,
            frame.SessionId,
            complete);
    }

    private static EacLogicalMessage?
        ParseComplete(
            DateTime timestampUtc,
            string direction,
            ulong sessionId,
            byte[] data)
    {
        if (!EacHandshakeParser.TryParseLogical(
                timestampUtc,
                direction,
                sessionId,
                data,
                out EacLogicalMessage? message))
        {
            return null;
        }

        return message;
    }
}