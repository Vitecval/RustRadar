using System.Collections.Concurrent;
using System.IO;
using System.Text;
using RustRadar.Protocol;

namespace RustRadar.Logging;

public sealed class RustMessageLogger :
    IDisposable
{
    private BlockingCollection<string>? _queue;

    private StreamWriter? _writer;

    private Task? _writerTask;

    private long _droppedLines;

    public string? FilePath
    {
        get;
        private set;
    }

    public bool IsRunning =>
        _writer != null;

    public long DroppedLines =>
        Interlocked.Read(
            ref _droppedLines);

    public void Start()
    {
        if (_writer != null)
            return;

        Interlocked.Exchange(
            ref _droppedLines,
            0);

        string folder =
            Path.Combine(
                AppContext.BaseDirectory,
                "Logs");

        Directory.CreateDirectory(
            folder);

        FilePath =
            Path.Combine(
                folder,
                $"rust_messages_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.tsv");

        _queue =
            new BlockingCollection<string>(
                new ConcurrentQueue<string>(),
                boundedCapacity: 100_000);

        _writer =
            new StreamWriter(
                FilePath,
                append: false,
                new UTF8Encoding(false),
                bufferSize: 1024 * 1024);

        _writer.WriteLine(
            "timestamp\t" +
            "direction\t" +
            "rawType\t" +
            "kind\t" +
            "name\t" +
            "packetLength\t" +
            "protected\t" +
            "bodyLength\t" +
            "positionShape\t" +
            "counter\t" +
            "counterStatus\t" +
            "counterDelta\t" +
            "flags\t" +
            "bodyHex\t" +
            "authTagHex");

        BlockingCollection<string> queue =
            _queue;

        StreamWriter writer =
            _writer;

        _writerTask =
            Task.Run(
                () => WriterLoop(
                    queue,
                    writer));
    }

    public void Log(
        RustWireMessageInfo message)
    {
        BlockingCollection<string>? queue =
            _queue;

        if (queue == null ||
            queue.IsAddingCompleted)
        {
            return;
        }

        byte[] body =
            message.IsProtected
                ? message.ProtectedBody
                : message.PlainBody;

        string bodyHex =
            body.Length > 0
                ? Convert.ToHexString(
                    body)
                : "";

        string authTagHex =
            message.AuthenticationTag.Length > 0
                ? Convert.ToHexString(
                    message.AuthenticationTag)
                : "";

        string counter =
            message.Counter.HasValue
                ? message.Counter.Value.ToString()
                : "";

        string flags =
            message.ProtectionFlags.HasValue
                ? $"0x{message.ProtectionFlags.Value:X4}"
                : "";

        string counterDelta =
            message.CounterDelta.HasValue
                ? message.CounterDelta.Value.ToString()
                : "";

        string line =
            $"{message.TimestampUtc:O}\t" +
            $"{message.Direction}\t" +
            $"0x{message.RawType:X2}\t" +
            $"{message.Kind}\t" +
            $"{message.Name}\t" +
            $"{message.PacketLength}\t" +
            $"{(message.IsProtected ? 1 : 0)}\t" +
            $"{message.BodyLength}\t" +
            $"{message.PositionShape}\t" +
            $"{counter}\t" +
            $"{message.CounterStatus}\t" +
            $"{counterDelta}\t" +
            $"{flags}\t" +
            $"{bodyHex}\t" +
            $"{authTagHex}";

        if (!queue.TryAdd(
                line))
        {
            Interlocked.Increment(
                ref _droppedLines);
        }
    }

    public void LogMarker(
        string text)
    {
        BlockingCollection<string>? queue =
            _queue;

        if (queue == null ||
            queue.IsAddingCompleted)
        {
            return;
        }

        text =
            text
                .Replace('\t', ' ')
                .Replace('\r', ' ')
                .Replace('\n', ' ');

        string line =
            $"{DateTime.UtcNow:O}\t" +
            $"MARKER\t" +
            $"-\t" +
            $"-\t" +
            $"{text}\t" +
            $"0\t" +
            $"0\t" +
            $"0\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-";

        if (!queue.TryAdd(
                line))
        {
            Interlocked.Increment(
                ref _droppedLines);
        }
    }

    private static void WriterLoop(
        BlockingCollection<string> queue,
        StreamWriter writer)
    {
        try
        {
            foreach (string line
                     in queue.GetConsumingEnumerable())
            {
                writer.WriteLine(
                    line);
            }
        }
        finally
        {
            writer.Flush();
        }
    }

    public void Stop()
    {
        BlockingCollection<string>? queue =
            _queue;

        StreamWriter? writer =
            _writer;

        Task? task =
            _writerTask;

        if (queue == null ||
            writer == null)
        {
            return;
        }

        try
        {
            queue.CompleteAdding();

            task?.Wait(
                TimeSpan.FromSeconds(15));
        }
        catch
        {
        }

        try
        {
            writer.Flush();
            writer.Dispose();
        }
        catch
        {
        }

        try
        {
            queue.Dispose();
        }
        catch
        {
        }

        _queue = null;
        _writer = null;
        _writerTask = null;
    }

    public void Dispose()
    {
        Stop();
    }
}