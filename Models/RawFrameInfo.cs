namespace RustRadar.Models;

public sealed record RawFrameInfo(
    DateTime TimestampUtc,

    // FRAME or REASSEMBLED
    string Kind,

    // S2C or C2S
    string Direction,

    int DatagramSequence,

    byte Reliability,
    bool IsSplit,

    int? ReliableIndex,
    int? SequencingIndex,
    int? OrderingIndex,
    byte? OrderingChannel,

    uint? SplitCount,
    ushort? SplitId,
    uint? SplitIndex,

    int PayloadLength,
    byte? FirstByte,

    // FULL payload, not truncated
    string Hex);