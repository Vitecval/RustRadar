using System.Collections.Concurrent;
using System.IO;
using System.Text;
using RustRadar.Models;

namespace RustRadar.Logging;

public sealed class CaptureFileLogger : IDisposable
{
    private BlockingCollection<string>? _queue;

    private Task? _writerTask;
    private StreamWriter? _writer;

    private long _droppedLines;

    public string? FilePath { get; private set; }

    public long DroppedLines =>
        Interlocked.Read(ref _droppedLines);

    public bool IsRunning =>
        _writer != null;

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

        Directory.CreateDirectory(folder);

        FilePath =
            Path.Combine(
                folder,
                $"rust_raw_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.tsv");

        /*
         * Bounded queue prevents capture from eating unlimited
         * memory if disk writing somehow falls behind.
         */
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
            "kind\t" +
            "direction\t" +
            "datagramSequence\t" +
            "reliability\t" +
            "isSplit\t" +
            "reliableIndex\t" +
            "sequencingIndex\t" +
            "orderingIndex\t" +
            "orderingChannel\t" +
            "splitCount\t" +
            "splitId\t" +
            "splitIndex\t" +
            "payloadLength\t" +
            "firstByte\t" +
            "hex");

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

    public void LogRawFrame(
        RawFrameInfo frame)
    {
        BlockingCollection<string>? queue =
            _queue;

        if (queue == null ||
            queue.IsAddingCompleted)
        {
            return;
        }

        string line =
            $"{frame.TimestampUtc:O}\t" +
            $"{frame.Kind}\t" +
            $"{frame.Direction}\t" +
            $"{frame.DatagramSequence}\t" +
            $"{frame.Reliability}\t" +
            $"{(frame.IsSplit ? 1 : 0)}\t" +
            $"{NullableToString(frame.ReliableIndex)}\t" +
            $"{NullableToString(frame.SequencingIndex)}\t" +
            $"{NullableToString(frame.OrderingIndex)}\t" +
            $"{NullableToString(frame.OrderingChannel)}\t" +
            $"{NullableToString(frame.SplitCount)}\t" +
            $"{NullableToString(frame.SplitId)}\t" +
            $"{NullableToString(frame.SplitIndex)}\t" +
            $"{frame.PayloadLength}\t" +
            $"{FormatByte(frame.FirstByte)}\t" +
            $"{frame.Hex}";

        if (!queue.TryAdd(line))
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
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"-\t" +
            $"0\t" +
            $"-\t" +
            $"{text}";

        if (!queue.TryAdd(line))
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
                writer.WriteLine(line);
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

        Task? writerTask =
            _writerTask;

        if (queue == null ||
            writer == null)
        {
            return;
        }

        try
        {
            queue.CompleteAdding();

            writerTask?.Wait(
                TimeSpan.FromSeconds(15));
        }
        catch
        {
            // We still attempt to flush below.
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

    private static string NullableToString<T>(
        T? value)
        where T : struct
    {
        return value.HasValue
            ? value.Value.ToString() ?? ""
            : "";
    }

    private static string FormatByte(
        byte? value)
    {
        return value.HasValue
            ? $"0x{value.Value:X2}"
            : "";
    }

    public void Dispose()
    {
        Stop();
    }
}