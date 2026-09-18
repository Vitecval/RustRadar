using System.Buffers.Binary;
using System.IO;
using System.Net.WebSockets;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using RustRadar.Models;

namespace RustRadar.Relay;

public sealed record RustRelayStatsSnapshot(
    long Packets,
    long Positions,
    long Destroys,
    long WebSocketConnections,
    long HttpBatches);

public sealed class RustRelayServer :
    IDisposable
{
    private const int TimestampMagic =
        0x53545252;

    private const int MaximumMessageSize =
        16 * 1024 * 1024;

    private readonly RelayEntityManager
        _entities;

    private WebApplication?
        _app;

    private long _packets;
    private long _positions;
    private long _destroys;
    private long _wsConnections;
    private long _httpBatches;

    private string _token =
        "";

    public event Action<string>?
        StatusChanged;

    public event Action<RelayPacketInfo>?
        PacketObserved;

    public bool IsRunning =>
        _app != null;

    public RustRelayServer(
        RelayEntityManager entities)
    {
        _entities =
            entities;
    }

    public async Task StartAsync(
        string listenUrl,
        string authToken)
    {
        if (_app != null)
        {
            throw new InvalidOperationException(
                "RustRelay receiver is already running.");
        }

        if (string.IsNullOrWhiteSpace(
                listenUrl))
        {
            throw new ArgumentException(
                "Relay listen URL is required.",
                nameof(listenUrl));
        }

        if (string.IsNullOrWhiteSpace(
                authToken))
        {
            throw new ArgumentException(
                "Relay token is required.",
                nameof(authToken));
        }

        _token =
            authToken;

        ResetStatistics();

        _entities.Clear();

        var builder =
            WebApplication.CreateBuilder(
                new WebApplicationOptions
                {
                    Args =
                        Array.Empty<string>(),

                    ApplicationName =
                        typeof(RustRelayServer)
                            .Assembly
                            .FullName
                });

        /*
         * Prevent ASP.NET from filling the Visual
         * Studio output window with a line per request.
         */
        builder.Logging.ClearProviders();

        builder.WebHost.UseUrls(
            listenUrl);

        WebApplication app =
            builder.Build();

        app.UseWebSockets(
            new WebSocketOptions
            {
                KeepAliveInterval =
                    TimeSpan.FromSeconds(20)
            });

        /*
         * Simple test endpoint.
         *
         * This deliberately doesn't require auth so you
         * can test connectivity from the Rust server PC:
         *
         * curl http://RADAR-PC-IP:28090/health
         */
        app.MapGet(
            "/health",
            () =>
                Results.Text(
                    "RustRadar relay receiver OK"));

        /*
         * =========================================================
         * LIVE WEBSOCKET INGEST
         * =========================================================
         */

        app.Map(
            "/ws/ingest",
            async context =>
            {
                if (!IsAuthorized(
                        context))
                {
                    context.Response.StatusCode =
                        StatusCodes
                            .Status401Unauthorized;

                    return;
                }

                if (!context.WebSockets
                        .IsWebSocketRequest)
                {
                    context.Response.StatusCode =
                        StatusCodes
                            .Status400BadRequest;

                    return;
                }

                string wipeId =
                    GetWipeId(
                        context);

                using WebSocket socket =
                    await context.WebSockets
                        .AcceptWebSocketAsync();

                Interlocked.Increment(
                    ref _wsConnections);

                StatusChanged?.Invoke(
                    $"RustRelay WebSocket connected. Wipe={wipeId}");

                long? serverTime =
                    null;

                try
                {
                    byte[] receiveBuffer =
                        new byte[64 * 1024];

                    while (
                        socket.State ==
                        WebSocketState.Open &&
                        !context
                            .RequestAborted
                            .IsCancellationRequested)
                    {
                        using var message =
                            new MemoryStream();

                        WebSocketReceiveResult result;

                        do
                        {
                            result =
                                await socket.ReceiveAsync(
                                    new ArraySegment<byte>(
                                        receiveBuffer),
                                    context
                                        .RequestAborted);

                            if (result.MessageType ==
                                WebSocketMessageType.Close)
                            {
                                await socket.CloseAsync(
                                    WebSocketCloseStatus
                                        .NormalClosure,
                                    "Closing",
                                    CancellationToken.None);

                                return;
                            }

                            if (result.MessageType !=
                                WebSocketMessageType.Binary)
                            {
                                continue;
                            }

                            if (message.Length +
                                result.Count >
                                MaximumMessageSize)
                            {
                                throw new InvalidDataException(
                                    "RustRelay message exceeded safety limit.");
                            }

                            message.Write(
                                receiveBuffer,
                                0,
                                result.Count);
                        }
                        while (!result.EndOfMessage);

                        if (result.MessageType !=
                            WebSocketMessageType.Binary)
                        {
                            continue;
                        }

                        byte[] data =
                            message.ToArray();

                        /*
                         * RustRelay timestamp marker:
                         *
                         * int32 magic
                         * int64 serverTime
                         */
                        if (TryParseTimestampMarker(
                                data,
                                out long timestamp))
                        {
                            serverTime =
                                timestamp;

                            continue;
                        }

                        /*
                         * Facepunch says to discard normal
                         * WS packets until we've received the
                         * first server-time marker.
                         */
                        if (!serverTime.HasValue)
                            continue;

                        ProcessRelayPacket(
                            data,
                            wipeId,
                            serverTime);
                    }
                }
                catch (OperationCanceledException)
                {
                }
                catch (WebSocketException ex)
                {
                    StatusChanged?.Invoke(
                        $"RustRelay WS closed: {ex.Message}");
                }
                catch (Exception ex)
                {
                    StatusChanged?.Invoke(
                        $"RustRelay WS error: {ex.Message}");
                }
                finally
                {
                    StatusChanged?.Invoke(
                        "RustRelay WebSocket disconnected.");
                }
            });

        /*
         * =========================================================
         * HTTP PACKET BATCH
         * =========================================================
         */

        app.MapPost(
            "/api/Packet",
            async context =>
            {
                if (!IsAuthorized(
                        context))
                {
                    context.Response.StatusCode =
                        StatusCodes
                            .Status401Unauthorized;

                    return;
                }

                byte[] data =
                    await ReadRequestBodyAsync(
                        context);

                string wipeId =
                    GetWipeId(
                        context);

                long? serverTime =
                    GetServerTime(
                        context);

                Interlocked.Increment(
                    ref _httpBatches);

                /*
                 * The HTTP endpoint is documented as
                 * length-prefixed packets. All relay
                 * integers are little-endian.
                 *
                 * We use int32 LE lengths here and fall
                 * back to one raw packet if the body
                 * doesn't form a valid batch.
                 */
                if (!TryProcessPacketBatch(
                        data,
                        wipeId,
                        serverTime))
                {
                    ProcessRelayPacket(
                        data,
                        wipeId,
                        serverTime);
                }

                context.Response.StatusCode =
                    StatusCodes.Status200OK;
            });

        /*
         * =========================================================
         * SNAPSHOT
         *
         * We accept it now but don't deserialize the
         * protobuf world snapshot in this first pass.
         * =========================================================
         */

        app.MapPost(
            "/api/Snapshot",
            async context =>
            {
                if (!IsAuthorized(
                        context))
                {
                    context.Response.StatusCode =
                        StatusCodes
                            .Status401Unauthorized;

                    return;
                }

                byte[] data =
                    await ReadRequestBodyAsync(
                        context);

                StatusChanged?.Invoke(
                    $"RustRelay snapshot received: {data.Length:N0} bytes");

                context.Response.StatusCode =
                    StatusCodes.Status200OK;
            });

        /*
         * Map snapshot isn't required for our XY/XZ
         * point radar yet. Accept and discard.
         */
        app.MapPost(
            "/api/MapSnapshot",
            async context =>
            {
                if (!IsAuthorized(
                        context))
                {
                    context.Response.StatusCode =
                        StatusCodes
                            .Status401Unauthorized;

                    return;
                }

                await DrainRequestAsync(
                    context);

                context.Response.StatusCode =
                    StatusCodes.Status200OK;
            });

        app.MapPost(
            "/api/Manifest",
            async context =>
            {
                if (!IsAuthorized(
                        context))
                {
                    context.Response.StatusCode =
                        StatusCodes
                            .Status401Unauthorized;

                    return;
                }

                await DrainRequestAsync(
                    context);

                context.Response.StatusCode =
                    StatusCodes.Status200OK;
            });

        app.MapPost(
            "/api/StringPool",
            async context =>
            {
                if (!IsAuthorized(
                        context))
                {
                    context.Response.StatusCode =
                        StatusCodes
                            .Status401Unauthorized;

                    return;
                }

                await DrainRequestAsync(
                    context);

                context.Response.StatusCode =
                    StatusCodes.Status200OK;
            });

        /*
         * This should NOT be called with the server
         * configuration we're going to use:
         *
         * relay.cfg_encryptpackets false
         * relay.cfg_sendconsoledata false
         *
         * If it is called, the status line tells us
         * immediately that something is configured wrong.
         */
        app.MapPost(
            "/api/Auth/exchangeKey",
            context =>
            {
                StatusChanged?.Invoke(
                    "RustRelay requested encryption key exchange. " +
                    "Check relay.cfg_encryptpackets and relay.cfg_sendconsoledata.");

                context.Response.StatusCode =
                    StatusCodes.Status400BadRequest;

                return Task.CompletedTask;
            });

        try
        {
            await app.StartAsync();

            _app =
                app;

            StatusChanged?.Invoke(
                $"RustRelay receiver listening on {listenUrl}");
        }
        catch
        {
            await app.DisposeAsync();

            throw;
        }
    }

    public async Task StopAsync()
    {
        WebApplication? app =
            _app;

        if (app == null)
            return;

        _app =
            null;

        try
        {
            await app.StopAsync(
                TimeSpan.FromSeconds(5));
        }
        catch
        {
        }

        try
        {
            await app.DisposeAsync();
        }
        catch
        {
        }

        StatusChanged?.Invoke(
            "RustRelay receiver stopped.");
    }

    private bool IsAuthorized(
        HttpContext context)
    {
        string? bearer =
            context.Request.Headers
                .Authorization
                .FirstOrDefault();

        if (!string.IsNullOrWhiteSpace(
                bearer) &&
            bearer.StartsWith(
                "Bearer ",
                StringComparison.OrdinalIgnoreCase))
        {
            string supplied =
                bearer["Bearer ".Length..]
                    .Trim();

            if (string.Equals(
                    supplied,
                    _token,
                    StringComparison.Ordinal))
            {
                return true;
            }
        }

        /*
         * Facepunch also supplies access_token in the
         * WebSocket query string.
         */
        string suppliedQuery =
            context.Request.Query[
                "access_token"]
                .ToString();

        return string.Equals(
            suppliedQuery,
            _token,
            StringComparison.Ordinal);
    }

    private static string GetWipeId(
        HttpContext context)
    {
        string header =
            context.Request.Headers[
                "X-Wipe-Id"]
                .ToString();

        if (!string.IsNullOrWhiteSpace(
                header))
        {
            return header;
        }

        string query =
            context.Request.Query[
                "wipeId"]
                .ToString();

        return query;
    }

    private static long? GetServerTime(
        HttpContext context)
    {
        string value =
            context.Request.Headers[
                "X-Server-Time"]
                .ToString();

        if (long.TryParse(
                value,
                out long parsed))
        {
            return parsed;
        }

        return null;
    }

    private static bool TryParseTimestampMarker(
        byte[] data,
        out long serverTime)
    {
        serverTime = 0;

        if (data.Length != 12)
            return false;

        int magic =
            BinaryPrimitives
                .ReadInt32LittleEndian(
                    data.AsSpan(
                        0,
                        4));

        if (magic !=
            TimestampMagic)
        {
            return false;
        }

        serverTime =
            BinaryPrimitives
                .ReadInt64LittleEndian(
                    data.AsSpan(
                        4,
                        8));

        return true;
    }

    private bool TryProcessPacketBatch(
        byte[] data,
        string wipeId,
        long? serverTime)
    {
        if (data.Length < 5)
            return false;

        int offset = 0;
        int packets = 0;

        while (offset <
               data.Length)
        {
            if (offset + 4 >
                data.Length)
            {
                return false;
            }

            int length =
                BinaryPrimitives
                    .ReadInt32LittleEndian(
                        data.AsSpan(
                            offset,
                            4));

            offset += 4;

            if (length <= 0 ||
                length >
                MaximumMessageSize ||
                offset + length >
                data.Length)
            {
                return false;
            }

            ProcessRelayPacket(
                data.AsSpan(
                        offset,
                        length)
                    .ToArray(),

                wipeId,
                serverTime);

            offset +=
                length;

            packets++;
        }

        return packets > 0;
    }

    private void ProcessRelayPacket(
        byte[] packet,
        string wipeId,
        long? serverTime)
    {
        RelayPacketInfo? info =
            RustRelayPacketParser.Parse(
                packet,
                wipeId,
                serverTime);

        if (info == null)
            return;

        Interlocked.Increment(
            ref _packets);

        if (info.Position != null)
        {
            Interlocked.Increment(
                ref _positions);

            _entities.ApplyPosition(
                info.Position,
                serverTime);
        }

        if (info.Destroy != null)
        {
            Interlocked.Increment(
                ref _destroys);

            _entities.Remove(
                info.Destroy.EntityId);
        }

        PacketObserved?.Invoke(
            info);
    }

    private static async Task<byte[]>
        ReadRequestBodyAsync(
            HttpContext context)
    {
        using var stream =
            new MemoryStream();

        await context.Request.Body
            .CopyToAsync(
                stream,
                context.RequestAborted);

        if (stream.Length >
            MaximumMessageSize)
        {
            throw new InvalidDataException(
                "RustRelay HTTP request too large.");
        }

        return stream.ToArray();
    }

    private static async Task
        DrainRequestAsync(
            HttpContext context)
    {
        byte[] buffer =
            new byte[64 * 1024];

        while (await context.Request.Body.ReadAsync(
                   buffer,
                   context.RequestAborted) > 0)
        {
        }
    }

    public RustRelayStatsSnapshot
        GetStatistics()
    {
        return new RustRelayStatsSnapshot(
            Interlocked.Read(
                ref _packets),

            Interlocked.Read(
                ref _positions),

            Interlocked.Read(
                ref _destroys),

            Interlocked.Read(
                ref _wsConnections),

            Interlocked.Read(
                ref _httpBatches));
    }

    private void ResetStatistics()
    {
        Interlocked.Exchange(
            ref _packets,
            0);

        Interlocked.Exchange(
            ref _positions,
            0);

        Interlocked.Exchange(
            ref _destroys,
            0);

        Interlocked.Exchange(
            ref _wsConnections,
            0);

        Interlocked.Exchange(
            ref _httpBatches,
            0);
    }

    public void Dispose()
    {
        try
        {
            StopAsync()
                .GetAwaiter()
                .GetResult();
        }
        catch
        {
        }
    }
}