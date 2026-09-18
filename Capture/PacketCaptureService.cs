using System.Net;
using PacketDotNet;
using RustRadar.Models;
using RustRadar.Protocol;
using RustRadar.RakNet;
using SharpPcap;
using SharpPcap.LibPcap;
using RustRadar.Logging;

namespace RustRadar.Capture;

public sealed record CaptureDeviceInfo(
    int Index,
    string Name,
    string Description)
{
    public override string ToString()
    {
        if (!string.IsNullOrWhiteSpace(
                Description))
        {
            return $"{Index}: {Description}";
        }

        return $"{Index}: {Name}";
    }
}

public sealed record CaptureStatsSnapshot(
    long UdpPackets,
    long RakNetDatagrams,
    long RakNetFrames,
    long SplitPacketsCompleted,

    long ApplicationPayloads,
    long ApplicationPayloadBytes,

    long RustMessages,

    long Entities,
    long EntityDestroy,
    long RpcMessages,
    long EntityPositions,
    long Effects,
    long EntityFlags,

    long ProtectedMessages,
    long PlainMessages,

    long OtherRustMessages,

    long Position36,
    long Position44,
    long PositionUnexpected,

    long CounterGaps,
    long CounterMissingMessages,
    long CounterOutOfOrder,
    long CounterDuplicates
);

public sealed class PacketCaptureService :
    IDisposable
{
    private ICaptureDevice? _device;

    private IPAddress? _serverIp;
    private ushort _serverPort;

    private readonly SplitPacketAssembler
        _splitAssembler =
            new();

    private readonly ProtectionCounterTracker
        _counterTracker =
            new();

    /*
     * EAC / NetProtect logical-message
     * reassembly.
     */
    private readonly EacMessageAssembler
        _eacAssembler =
            new();

    private readonly EacHandshakeLogger
        _eacHandshakeLogger =
            new();

    public string? EacHandshakeLogPath =>
        _eacHandshakeLogger.CurrentFilePath;

    private long _udpPackets;
    private long _rakNetDatagrams;
    private long _rakNetFrames;

    private long _splitPacketsCompleted;

    private long _applicationPayloads;
    private long _applicationPayloadBytes;

    private long _rustMessages;

    private long _entities;
    private long _entityDestroy;
    private long _rpcMessages;
    private long _entityPositions;
    private long _effects;
    private long _entityFlags;

    private long _protectedMessages;
    private long _plainMessages;

    private long _otherRustMessages;

    private long _position36;
    private long _position44;
    private long _positionUnexpected;

    private long _counterGaps;
    private long _counterMissingMessages;
    private long _counterOutOfOrder;
    private long _counterDuplicates;

    public bool IsRunning =>
        _device != null;

    public event Action<RawFrameInfo>?
        RawFrameObserved;

    public event Action<RustWireMessageInfo>?
        WireMessageObserved;

    /*
     * New event.
     *
     * Fires once an entire logical EAC message
     * has been reconstructed.
     */
    public event Action<EacLogicalMessage>?
        EacLogicalMessageObserved;

    public event Action<string>?
        StatusChanged;

    public IReadOnlyList<CaptureDeviceInfo>
        GetDevices()
    {
        var devices =
            LibPcapLiveDeviceList.Instance;

        var result =
            new List<CaptureDeviceInfo>();

        for (int i = 0;
             i < devices.Count;
             i++)
        {
            var device =
                devices[i];

            result.Add(
                new CaptureDeviceInfo(
                    i,
                    device.Name ?? "",
                    device.Description ?? ""));
        }

        return result;
    }

    public void Start(
        int deviceIndex,
        IPAddress serverIp,
        ushort serverPort)
    {
        if (_device != null)
        {
            throw new InvalidOperationException(
                "Capture is already running.");
        }

        var devices =
            LibPcapLiveDeviceList.Instance;

        if (deviceIndex < 0 ||
            deviceIndex >= devices.Count)
        {
            throw new ArgumentOutOfRangeException(
                nameof(deviceIndex));
        }

        ResetStatistics();

        _counterTracker.Reset();

        /*
         * Do not carry incomplete EAC fragments
         * from a previous capture session.
         */
        _eacAssembler.Clear();
        _eacHandshakeLogger.Start();

        _serverIp =
            serverIp;

        _serverPort =
            serverPort;

        ICaptureDevice device =
            devices[deviceIndex];

        try
        {
            device.Open(
                new DeviceConfiguration
                {
                    Mode =
                        DeviceModes.Promiscuous,

                    Immediate =
                        true,

                    ReadTimeout =
                        1000
                });

            device.Filter =
                $"udp and host {serverIp} and port {serverPort}";

            device.OnPacketArrival +=
                Device_OnPacketArrival;

            _device =
                device;

            device.StartCapture();

            StatusChanged?.Invoke(
                $"Capturing {serverIp}:{serverPort}");
        }
        catch
        {
            _eacHandshakeLogger.Stop();

            try
            {
                device.Dispose();
            }
            catch
            {
            }

            _device =
                null;

            throw;
        }
    }

    public void Stop()
    {
        ICaptureDevice? device =
            _device;

        if (device == null)
            return;

        _device =
            null;

        try
        {
            device.StopCapture();
        }
        catch
        {
        }

        try
        {
            device.OnPacketArrival -=
                Device_OnPacketArrival;

            device.Dispose();
        }
        catch
        {
        }

        /*
         * Throw away any half-completed EAC
         * handshake message.
         */
        _eacAssembler.Clear();

        _eacHandshakeLogger.Stop();

        StatusChanged?.Invoke(
            "Capture stopped.");
    }

    private void Device_OnPacketArrival(
        object sender,
        PacketCapture e)
    {
        try
        {
            RawCapture raw =
                e.GetPacket();

            DateTime timestampUtc =
                raw.Timeval.Date
                    .ToUniversalTime();

            Packet packet =
                Packet.ParsePacket(
                    raw.LinkLayerType,
                    raw.Data);

            IPv4Packet? ip =
                packet.Extract<IPv4Packet>();

            UdpPacket? udp =
                packet.Extract<UdpPacket>();

            if (ip == null ||
                udp == null ||
                _serverIp == null)
            {
                return;
            }

            bool serverToClient =
                ip.SourceAddress.Equals(
                    _serverIp) &&
                udp.SourcePort ==
                    _serverPort;

            bool clientToServer =
                ip.DestinationAddress.Equals(
                    _serverIp) &&
                udp.DestinationPort ==
                    _serverPort;

            if (!serverToClient &&
                !clientToServer)
            {
                return;
            }

            Interlocked.Increment(
                ref _udpPackets);

            byte[] payload =
                udp.PayloadData;

            if (payload == null ||
                payload.Length == 0)
            {
                return;
            }

            if (!RakNetParser.TryParseDatagram(
                    payload,
                    out RakNetDatagram?
                        datagram) ||
                datagram == null)
            {
                return;
            }

            Interlocked.Increment(
                ref _rakNetDatagrams);

            string direction =
                serverToClient
                    ? "S2C"
                    : "C2S";

            foreach (RakNetFrame frame
                     in datagram.Frames)
            {
                Interlocked.Increment(
                    ref _rakNetFrames);

                /*
                 * Always preserve literal
                 * RakNet frames.
                 */
                EmitRawRecord(
                    timestampUtc,
                    "FRAME",
                    direction,
                    datagram.SequenceNumber,
                    frame,
                    frame.Payload);

                byte[]? applicationPayload =
                    _splitAssembler.Process(
                        direction,
                        frame);

                if (applicationPayload == null)
                    continue;

                if (frame.IsSplit)
                {
                    Interlocked.Increment(
                        ref _splitPacketsCompleted);

                    EmitRawRecord(
                        timestampUtc,
                        "REASSEMBLED",
                        direction,
                        datagram.SequenceNumber,
                        frame,
                        applicationPayload);
                }

                Interlocked.Increment(
                    ref _applicationPayloads);

                Interlocked.Add(
                    ref _applicationPayloadBytes,
                    applicationPayload.Length);

                HandleApplicationPayload(
                    timestampUtc,
                    direction,
                    applicationPayload);
            }
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(
                $"Capture parse error: {ex.Message}");
        }
    }

    private void HandleApplicationPayload(
        DateTime timestampUtc,
        string direction,
        byte[] payload)
    {
        /*
         * ---------------------------------------
         * EAC / NetProtect handshake observation
         * ---------------------------------------
         *
         * Do this BEFORE RustWireMessageParser.
         *
         * We still allow the packet to continue
         * through the normal Rust parser afterward
         * so it remains present in rust_messages.tsv.
         */
        TryHandleEacMessage(
            timestampUtc,
            direction,
            payload);

        RustWireMessageInfo? parsed =
            RustWireMessageParser.Parse(
                payload,
                timestampUtc,
                direction);

        if (parsed == null)
            return;

        CounterTrackerResult counterResult =
            _counterTracker.Observe(
                direction,
                parsed.Counter,
                parsed.ProtectionFlags);

        RustWireMessageInfo message =
            parsed with
            {
                CounterStatus =
                    counterResult.Status,

                CounterDelta =
                    counterResult.Delta
            };

        Interlocked.Increment(
            ref _rustMessages);

        if (message.IsProtected)
        {
            Interlocked.Increment(
                ref _protectedMessages);
        }
        else
        {
            Interlocked.Increment(
                ref _plainMessages);
        }

        switch (message.Kind)
        {
            case RustWireMessageKind.Entities:

                Interlocked.Increment(
                    ref _entities);

                break;


            case RustWireMessageKind.EntityDestroy:

                Interlocked.Increment(
                    ref _entityDestroy);

                break;


            case RustWireMessageKind.RpcMessage:

                Interlocked.Increment(
                    ref _rpcMessages);

                break;


            case RustWireMessageKind.EntityPosition:

                Interlocked.Increment(
                    ref _entityPositions);

                break;


            case RustWireMessageKind.Effect:

                Interlocked.Increment(
                    ref _effects);

                break;


            case RustWireMessageKind.EntityFlags:

                Interlocked.Increment(
                    ref _entityFlags);

                break;


            case RustWireMessageKind.Other:

                Interlocked.Increment(
                    ref _otherRustMessages);

                break;
        }

        switch (message.PositionShape)
        {
            case RustPositionShape.Position36:

                Interlocked.Increment(
                    ref _position36);

                break;


            case RustPositionShape.Position44:

                Interlocked.Increment(
                    ref _position44);

                break;


            case RustPositionShape.Unexpected:

                Interlocked.Increment(
                    ref _positionUnexpected);

                break;
        }

        switch (message.CounterStatus)
        {
            case ProtectionCounterStatus.Gap:

                Interlocked.Increment(
                    ref _counterGaps);

                if (message.CounterDelta.HasValue &&
                    message.CounterDelta.Value > 1)
                {
                    Interlocked.Add(
                        ref _counterMissingMessages,
                        message.CounterDelta.Value - 1);
                }

                break;


            case ProtectionCounterStatus.OutOfOrder:

                Interlocked.Increment(
                    ref _counterOutOfOrder);

                break;


            case ProtectionCounterStatus.Duplicate:

                Interlocked.Increment(
                    ref _counterDuplicates);

                break;
        }

        WireMessageObserved?.Invoke(
            message);
    }

    private void TryHandleEacMessage(
        DateTime timestampUtc,
        string direction,
        byte[] payload)
    {
        /*
         * Needs:
         *
         * byte 0 = Rust message ID
         * bytes 1+ = EAC transport body
         */
        if (payload.Length <= 1)
            return;

        if (payload[0] !=
            EacHandshakeParser.RustMessageType)
        {
            return;
        }

        ReadOnlySpan<byte> body =
            payload.AsSpan(
                1);

        if (!EacHandshakeParser
                .TryParseTransport(
                    body,
                    out EacTransportFrame?
                        transport) ||
            transport == null)
        {
            return;
        }

        EacLogicalMessage? logical =
            _eacAssembler.Process(
                timestampUtc,
                direction,
                transport);

        /*
         * Most 0xA2 frames are transport pieces
         * or control messages.
         *
         * Only fire the event once an entire
         * logical EAC message exists.
         */
        if (logical == null)
            return;

        /*
         * Persist the fully reconstructed
         * logical EAC message before exposing
         * it to the rest of the application.
         */
        _eacHandshakeLogger.Write(
            logical);

        EacLogicalMessageObserved?.Invoke(
            logical);

        /*
         * Also send a concise line through the
         * existing status/event path so you can
         * immediately see that reassembly works
         * without changing the UI first.
         */
        string stepText =
            logical.Step.HasValue
                ? logical.Step.Value.ToString()
                : "-";

        StatusChanged?.Invoke(
            $"EAC {logical.Direction} " +
            $"session=0x{logical.SessionId:X} " +
            $"len={logical.Data.Length} " +
            $"type=0x{logical.MessageType:X2} " +
            $"stage={logical.Stage} " +
            $"step={stepText}");
    }

    private void EmitRawRecord(
        DateTime timestampUtc,
        string kind,
        string direction,
        int datagramSequence,
        RakNetFrame frame,
        byte[] payload)
    {
        byte? firstByte =
            payload.Length > 0
                ? payload[0]
                : null;

        string fullHex =
            payload.Length > 0
                ? Convert.ToHexString(
                    payload)
                : "";

        RawFrameObserved?.Invoke(
            new RawFrameInfo(
                timestampUtc,
                kind,
                direction,

                datagramSequence,

                frame.Reliability,
                frame.IsSplit,

                frame.ReliableIndex,
                frame.SequencingIndex,
                frame.OrderingIndex,
                frame.OrderingChannel,

                frame.SplitCount,
                frame.SplitId,
                frame.SplitIndex,

                payload.Length,
                firstByte,

                fullHex));
    }

    public CaptureStatsSnapshot
        GetStatistics()
    {
        return new CaptureStatsSnapshot(
            Interlocked.Read(
                ref _udpPackets),

            Interlocked.Read(
                ref _rakNetDatagrams),

            Interlocked.Read(
                ref _rakNetFrames),

            Interlocked.Read(
                ref _splitPacketsCompleted),

            Interlocked.Read(
                ref _applicationPayloads),

            Interlocked.Read(
                ref _applicationPayloadBytes),

            Interlocked.Read(
                ref _rustMessages),

            Interlocked.Read(
                ref _entities),

            Interlocked.Read(
                ref _entityDestroy),

            Interlocked.Read(
                ref _rpcMessages),

            Interlocked.Read(
                ref _entityPositions),

            Interlocked.Read(
                ref _effects),

            Interlocked.Read(
                ref _entityFlags),

            Interlocked.Read(
                ref _protectedMessages),

            Interlocked.Read(
                ref _plainMessages),

            Interlocked.Read(
                ref _otherRustMessages),

            Interlocked.Read(
                ref _position36),

            Interlocked.Read(
                ref _position44),

            Interlocked.Read(
                ref _positionUnexpected),

            Interlocked.Read(
                ref _counterGaps),

            Interlocked.Read(
                ref _counterMissingMessages),

            Interlocked.Read(
                ref _counterOutOfOrder),

            Interlocked.Read(
                ref _counterDuplicates));
    }

    private void ResetStatistics()
    {
        Interlocked.Exchange(
            ref _udpPackets,
            0);

        Interlocked.Exchange(
            ref _rakNetDatagrams,
            0);

        Interlocked.Exchange(
            ref _rakNetFrames,
            0);

        Interlocked.Exchange(
            ref _splitPacketsCompleted,
            0);

        Interlocked.Exchange(
            ref _applicationPayloads,
            0);

        Interlocked.Exchange(
            ref _applicationPayloadBytes,
            0);

        Interlocked.Exchange(
            ref _rustMessages,
            0);

        Interlocked.Exchange(
            ref _entities,
            0);

        Interlocked.Exchange(
            ref _entityDestroy,
            0);

        Interlocked.Exchange(
            ref _rpcMessages,
            0);

        Interlocked.Exchange(
            ref _entityPositions,
            0);

        Interlocked.Exchange(
            ref _effects,
            0);

        Interlocked.Exchange(
            ref _entityFlags,
            0);

        Interlocked.Exchange(
            ref _protectedMessages,
            0);

        Interlocked.Exchange(
            ref _plainMessages,
            0);

        Interlocked.Exchange(
            ref _otherRustMessages,
            0);

        Interlocked.Exchange(
            ref _position36,
            0);

        Interlocked.Exchange(
            ref _position44,
            0);

        Interlocked.Exchange(
            ref _positionUnexpected,
            0);

        Interlocked.Exchange(
            ref _counterGaps,
            0);

        Interlocked.Exchange(
            ref _counterMissingMessages,
            0);

        Interlocked.Exchange(
            ref _counterOutOfOrder,
            0);

        Interlocked.Exchange(
            ref _counterDuplicates,
            0);
    }

    public void Dispose()
    {
        Stop();
    }
}