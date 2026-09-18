using System.Buffers.Binary;

namespace RustRadar.RakNet;

public sealed class RakNetDatagram
{
    public byte Flags { get; init; }

    /// <summary>
    /// Low 32 bits of RakNet's source-system timestamp.
    /// This build has INCLUDE_TIMESTAMP_WITH_DATAGRAMS enabled.
    /// </summary>
    public uint SourceSystemTime { get; init; }

    /// <summary>
    /// Real 24-bit RakNet datagram sequence.
    /// </summary>
    public int SequenceNumber { get; init; }

    public List<RakNetFrame> Frames { get; } = new();
}

public sealed class RakNetFrame
{
    public byte Reliability { get; init; }

    public bool IsSplit { get; init; }

    public int? ReliableIndex { get; init; }

    public int? SequencingIndex { get; init; }

    public int? OrderingIndex { get; init; }

    public byte? OrderingChannel { get; init; }

    public uint? SplitCount { get; init; }

    public ushort? SplitId { get; init; }

    public uint? SplitIndex { get; init; }

    public int BitLength { get; init; }

    public byte[] Payload { get; init; } =
        Array.Empty<byte>();
}

public static class RakNetParser
{
    public static bool TryParseDatagram(
        ReadOnlySpan<byte> data,
        out RakNetDatagram? datagram)
    {
        datagram = null;

        /*
         * Connected Rust RakNet data packets:
         *
         * byte 0      datagram flags
         * byte 1..4   sourceSystemTime
         * byte 5..7   uint24 datagram sequence
         * byte 8..    internal RakNet frames
         *
         * Example:
         *
         * 84 00 82 52 97 00 00 00 ...
         * ^^ ^^^^^^^^^^^ ^^^^^^^^
         * fl timestamp   seq = 0
         */

        if (data.Length < 8)
            return false;

        byte datagramFlags =
            data[0];

        /*
         * Bit 7 = valid RakNet datagram.
         */
        if ((datagramFlags & 0x80) == 0)
            return false;

        /*
         * ACK.
         *
         * ACK/NAK packets don't contain internal
         * application frames in this format.
         */
        if ((datagramFlags & 0x40) != 0)
            return false;

        /*
         * NAK.
         */
        if ((datagramFlags & 0x20) != 0)
            return false;

        uint sourceSystemTime =
            BinaryPrimitives.ReadUInt32LittleEndian(
                data.Slice(1, 4));

        int sequence =
            ReadTriadLittleEndian(
                data.Slice(5, 3));

        var result =
            new RakNetDatagram
            {
                Flags =
                    datagramFlags,

                SourceSystemTime =
                    sourceSystemTime,

                SequenceNumber =
                    sequence
            };

        int offset = 8;

        while (offset < data.Length)
        {
            int frameStart =
                offset;

            if (!TryParseFrame(
                    data,
                    ref offset,
                    out RakNetFrame? frame))
            {
                /*
                 * Datagram may contain padding at the end.
                 *
                 * If we already decoded valid frames,
                 * don't throw the whole datagram away.
                 */
                if (offset == frameStart)
                    break;

                break;
            }

            if (frame != null)
            {
                result.Frames.Add(
                    frame);
            }
        }

        if (result.Frames.Count == 0)
            return false;

        datagram =
            result;

        return true;
    }

    private static bool TryParseFrame(
        ReadOnlySpan<byte> data,
        ref int offset,
        out RakNetFrame? frame)
    {
        frame = null;

        if (!CanRead(
                data,
                offset,
                3))
        {
            return false;
        }

        /*
         * First three bits = reliability.
         *
         * Example:
         *
         * 0x60 = 0110 0000
         *        ^^^
         *        reliability 3
         *
         * bit 4 = split packet flag
         */
        byte flags =
            data[offset++];

        byte reliability =
            (byte)((flags >> 5) & 0x07);

        bool split =
            (flags & 0x10) != 0;

        /*
         * IMPORTANT:
         *
         * Rust's RakNet build writes this field
         * little-endian.
         *
         * Example:
         *
         * 90 00 = 0x0090 = 144 bits
         *       = 18 bytes
         */
        ushort bitLength =
            BinaryPrimitives.ReadUInt16LittleEndian(
                data.Slice(
                    offset,
                    2));

        offset += 2;

        if (bitLength == 0)
            return false;

        int byteLength =
            (bitLength + 7) / 8;

        int? reliableIndex =
            null;

        int? sequencingIndex =
            null;

        int? orderingIndex =
            null;

        byte? orderingChannel =
            null;

        /*
         * Reliable
         * ReliableOrdered
         * ReliableSequenced
         * and ACK receipt variants.
         */
        if (HasReliableIndex(
                reliability))
        {
            if (!CanRead(
                    data,
                    offset,
                    3))
            {
                return false;
            }

            reliableIndex =
                ReadTriadLittleEndian(
                    data.Slice(
                        offset,
                        3));

            offset += 3;
        }

        /*
         * UnreliableSequenced
         * ReliableSequenced
         */
        if (HasSequencingIndex(
                reliability))
        {
            if (!CanRead(
                    data,
                    offset,
                    3))
            {
                return false;
            }

            sequencingIndex =
                ReadTriadLittleEndian(
                    data.Slice(
                        offset,
                        3));

            offset += 3;
        }

        /*
         * UnreliableSequenced
         * ReliableOrdered
         * ReliableSequenced
         * ReliableOrderedWithAckReceipt
         */
        if (HasOrderingIndex(
                reliability))
        {
            if (!CanRead(
                    data,
                    offset,
                    4))
            {
                return false;
            }

            orderingIndex =
                ReadTriadLittleEndian(
                    data.Slice(
                        offset,
                        3));

            offset += 3;

            orderingChannel =
                data[offset++];
        }

        uint? splitCount =
            null;

        ushort? splitId =
            null;

        uint? splitIndex =
            null;

        if (split)
        {
            if (!CanRead(
                    data,
                    offset,
                    10))
            {
                return false;
            }

            /*
             * Also little-endian in the RakNet build
             * used by this Rust connection.
             *
             * We verified this against actual split
             * traffic from the full connection capture.
             */

            splitCount =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    data.Slice(
                        offset,
                        4));

            offset += 4;

            splitId =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    data.Slice(
                        offset,
                        2));

            offset += 2;

            splitIndex =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    data.Slice(
                        offset,
                        4));

            offset += 4;

            /*
             * Don't allow corrupt packet metadata to
             * allocate something stupid.
             */
            if (splitCount == 0 ||
                splitCount > 4096 ||
                splitIndex >= splitCount)
            {
                return false;
            }
        }

        if (!CanRead(
                data,
                offset,
                byteLength))
        {
            return false;
        }

        byte[] payload =
            data
                .Slice(
                    offset,
                    byteLength)
                .ToArray();

        offset +=
            byteLength;

        frame =
            new RakNetFrame
            {
                Reliability =
                    reliability,

                IsSplit =
                    split,

                ReliableIndex =
                    reliableIndex,

                SequencingIndex =
                    sequencingIndex,

                OrderingIndex =
                    orderingIndex,

                OrderingChannel =
                    orderingChannel,

                SplitCount =
                    splitCount,

                SplitId =
                    splitId,

                SplitIndex =
                    splitIndex,

                BitLength =
                    bitLength,

                Payload =
                    payload
            };

        return true;
    }

    private static bool HasReliableIndex(
        byte reliability)
    {
        return reliability is
            2 or
            3 or
            4 or
            6 or
            7;
    }

    private static bool HasSequencingIndex(
        byte reliability)
    {
        return reliability is
            1 or
            4;
    }

    private static bool HasOrderingIndex(
        byte reliability)
    {
        return reliability is
            1 or
            3 or
            4 or
            7;
    }

    private static int ReadTriadLittleEndian(
        ReadOnlySpan<byte> data)
    {
        return
            data[0] |
            (data[1] << 8) |
            (data[2] << 16);
    }

    private static bool CanRead(
        ReadOnlySpan<byte> data,
        int offset,
        int count)
    {
        if (offset < 0 ||
            count < 0)
        {
            return false;
        }

        return offset <=
               data.Length - count;
    }
}