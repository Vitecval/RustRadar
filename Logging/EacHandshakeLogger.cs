using System.Globalization;
using System.IO;
using System.Text;
using RustRadar.Protocol;

namespace RustRadar.Logging;

public sealed class EacHandshakeLogger :
    IDisposable
{
    private readonly object
        _sync =
            new();

    private StreamWriter?
        _writer;

    private string?
        _currentFilePath;

    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                return _writer != null;
            }
        }
    }

    public string? CurrentFilePath
    {
        get
        {
            lock (_sync)
            {
                return _currentFilePath;
            }
        }
    }

    public void Start(
        string? directory = null)
    {
        lock (_sync)
        {
            StopInternal();

            directory ??=
                AppContext.BaseDirectory;

            Directory.CreateDirectory(
                directory);

            string timestamp =
                DateTime.Now.ToString(
                    "yyyy-MM-dd_HH-mm-ss",
                    CultureInfo.InvariantCulture);

            string baseName =
                $"eac_handshake_{timestamp}";

            string path =
                GetUniquePath(
                    directory,
                    baseName);

            FileStream stream =
                new(
                    path,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.Read);

            _writer =
                new StreamWriter(
                    stream,
                    new UTF8Encoding(
                        encoderShouldEmitUTF8Identifier:
                            false))
                {
                    AutoFlush =
                        true
                };

            _currentFilePath =
                path;

            _writer.WriteLine(
                string.Join(
                    '\t',
                    "timestampUtc",
                    "direction",
                    "sessionId",
                    "sessionIdHex",
                    "dataLength",
                    "declaredLength",
                    "headerVersion",
                    "messageId",
                    "protocolFamily",
                    "messageType",
                    "messageTypeHex",
                    "stage",
                    "step",
                    "lengthMatches",
                    "dataHex"));
        }
    }

    public void Write(
        EacLogicalMessage message)
    {
        lock (_sync)
        {
            StreamWriter? writer =
                _writer;

            if (writer == null)
                return;

            string step =
                message.Step.HasValue
                    ? message.Step.Value.ToString(
                        CultureInfo.InvariantCulture)
                    : "";

            string dataHex =
                message.Data.Length > 0
                    ? Convert.ToHexString(
                        message.Data)
                    : "";

            writer.WriteLine(
                string.Join(
                    '\t',

                    message.TimestampUtc
                        .ToString(
                            "O",
                            CultureInfo.InvariantCulture),

                    message.Direction,

                    message.SessionId
                        .ToString(
                            CultureInfo.InvariantCulture),

                    $"0x{message.SessionId:X}",

                    message.Data.Length
                        .ToString(
                            CultureInfo.InvariantCulture),

                    message.DeclaredLength
                        .ToString(
                            CultureInfo.InvariantCulture),

                    message.HeaderVersion
                        .ToString(
                            CultureInfo.InvariantCulture),

                    message.MessageId
                        .ToString(
                            CultureInfo.InvariantCulture),

                    message.ProtocolFamily
                        .ToString(
                            CultureInfo.InvariantCulture),

                    message.MessageType
                        .ToString(
                            CultureInfo.InvariantCulture),

                    $"0x{message.MessageType:X2}",

                    message.Stage
                        .ToString(
                            CultureInfo.InvariantCulture),

                    step,

                    message.LengthMatches
                        ? "1"
                        : "0",

                    dataHex));
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            StopInternal();
        }
    }

    private void StopInternal()
    {
        if (_writer != null)
        {
            try
            {
                _writer.Flush();
            }
            catch
            {
            }

            try
            {
                _writer.Dispose();
            }
            catch
            {
            }
        }

        _writer =
            null;
    }

    private static string GetUniquePath(
        string directory,
        string baseName)
    {
        string first =
            Path.Combine(
                directory,
                $"{baseName}.tsv");

        if (!File.Exists(first))
        {
            return first;
        }

        for (int index = 2;
             index < 10000;
             index++)
        {
            string candidate =
                Path.Combine(
                    directory,
                    $"{baseName}_{index}.tsv");

            if (!File.Exists(
                    candidate))
            {
                return candidate;
            }
        }

        return Path.Combine(
            directory,
            $"{baseName}_{Guid.NewGuid():N}.tsv");
    }

    public void Dispose()
    {
        Stop();
    }
}