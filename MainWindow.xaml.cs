using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Windows;
using System.Windows.Threading;
using RustRadar.Capture;
using RustRadar.Logging;
using RustRadar.Models;
using RustRadar.Protocol;
using RustRadar.Relay;

namespace RustRadar;

public partial class MainWindow : Window
{
    /*
     * =============================================================
     * PASSIVE NETWORK CAPTURE
     * =============================================================
     */

    private readonly PacketCaptureService
        _capture = new();

    private readonly EntityManager
    _passiveEntities =
        new();

    private long _passiveUiSample;

    private ulong?
    _selfEntityId;

    private readonly CaptureFileLogger
        _fileLogger = new();

    private readonly RustMessageLogger
        _rustMessageLogger = new();


    /*
     * =============================================================
     * RUST RELAY
     * =============================================================
     */

    private readonly RelayEntityManager
        _relayEntities = new();

    private readonly RustRelayServer
        _relayServer;

    private long _relayUiSample;


    /*
     * =============================================================
     * UI
     * =============================================================
     */

    private readonly ConcurrentQueue<string>
        _logQueue = new();

    private readonly DispatcherTimer
        _uiTimer;


    public MainWindow()
    {
        /*
         * RustRelayServer needs the entity manager.
         */
        _relayServer =
            new RustRelayServer(
                _relayEntities);

        InitializeComponent();


        /*
         * =========================================================
         * PASSIVE CAPTURE EVENTS
         * =========================================================
         */

        _capture.RawFrameObserved +=
            Capture_RawFrameObserved;

        _capture.WireMessageObserved +=
            Capture_WireMessageObserved;

        _capture.StatusChanged +=
            Capture_StatusChanged;


        /*
         * =========================================================
         * RELAY EVENTS
         * =========================================================
         */

        _relayServer.StatusChanged +=
            RelayServer_StatusChanged;

        _relayServer.PacketObserved +=
            RelayServer_PacketObserved;


        /*
         * =========================================================
         * UI TIMER
         * =========================================================
         */

        _uiTimer =
            new DispatcherTimer
            {
                Interval =
                    TimeSpan.FromMilliseconds(
                        250)
            };

        _uiTimer.Tick +=
            UiTimer_Tick;

        _uiTimer.Start();

        if (NetProtect0100Decryptor
        .SelfTest(
            out string cryptoTest))
        {
            _logQueue.Enqueue(
                $"[NETPROTECT] {cryptoTest}");
        }
        else
        {
            _logQueue.Enqueue(
                $"[NETPROTECT] FAILED: {cryptoTest}");
        }

        RefreshDevices();
    }


    /*
     * =============================================================
     * DEVICE / CAPTURE SETUP
     * =============================================================
     */

    private void RefreshDevices()
    {
        try
        {
            IReadOnlyList<CaptureDeviceInfo>
                devices =
                    _capture.GetDevices();

            DeviceComboBox.ItemsSource =
                devices;

            if (devices.Count > 0)
            {
                DeviceComboBox.SelectedIndex =
                    0;
            }

            StatusTextBlock.Text =
                $"Found {devices.Count} capture adapter(s).";
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.ToString(),
                "Npcap / SharpPcap error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    private void RefreshDevicesButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_capture.IsRunning)
        {
            MessageBox.Show(
                "Stop passive capture first.");

            return;
        }

        RefreshDevices();
    }


    /*
     * =============================================================
     * START PASSIVE CAPTURE
     * =============================================================
     */

    private void StartCaptureButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (DeviceComboBox.SelectedItem
            is not CaptureDeviceInfo device)
        {
            MessageBox.Show(
                "Select a network adapter.");

            return;
        }

        if (!IPAddress.TryParse(
                ServerIpTextBox.Text.Trim(),
                out IPAddress? ip))
        {
            MessageBox.Show(
                "Invalid server IP.");

            return;
        }

        if (!ushort.TryParse(
                ServerPortTextBox.Text.Trim(),
                out ushort port))
        {
            MessageBox.Show(
                "Invalid server port.");

            return;
        }

        try
        {
            PacketLogListBox.Items.Clear();

            while (_logQueue.TryDequeue(
                       out _))
            {
            }

            _passiveEntities.Clear();

            Interlocked.Exchange(
                ref _passiveUiSample,
                0);

            _selfEntityId =
    null;

            /*
             * Create both logs.
             */
            _fileLogger.Start();

            _rustMessageLogger.Start();


            string startMarker =
                $"CAPTURE_START " +
                $"server={ip}:{port} " +
                $"adapter={device.Description}";

            _fileLogger.LogMarker(
                startMarker);

            _rustMessageLogger.LogMarker(
                startMarker);


            try
            {
                _capture.Start(
                    device.Index,
                    ip,
                    port);
            }
            catch
            {
                _fileLogger.Stop();

                _rustMessageLogger.Stop();

                throw;
            }


            StartCaptureButton.IsEnabled =
                false;

            StopCaptureButton.IsEnabled =
                true;


            StatusTextBlock.Text =
                $"Passive capture active | " +
                $"Raw: {_fileLogger.FilePath} | " +
                $"Messages: {_rustMessageLogger.FilePath}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.ToString(),
                "Capture failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    /*
     * =============================================================
     * STOP PASSIVE CAPTURE
     * =============================================================
     */

    private void StopCaptureButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        string? rawPath =
            _fileLogger.FilePath;

        string? messagePath =
            _rustMessageLogger.FilePath;


        _fileLogger.LogMarker(
            "CAPTURE_END");

        _rustMessageLogger.LogMarker(
            "CAPTURE_END");


        /*
         * Stop capture first so no new frames enter
         * either logger while they're flushing.
         */
        _capture.Stop();


        _fileLogger.Stop();

        _rustMessageLogger.Stop();


        StartCaptureButton.IsEnabled =
            true;

        StopCaptureButton.IsEnabled =
            false;


        StatusTextBlock.Text =
            $"Capture saved | " +
            $"Raw: {rawPath} | " +
            $"Messages: {messagePath}";
    }


    /*
     * =============================================================
     * RAW RAKNET LOGGING
     * =============================================================
     */

    private void Capture_RawFrameObserved(
        RawFrameInfo frame)
    {
        /*
         * Every parsed RakNet frame is written
         * to the raw TSV.
         *
         * We do not spam these into WPF.
         */
        _fileLogger.LogRawFrame(
            frame);
    }


    /*
     * =============================================================
     * RUST WIRE MESSAGE INSPECTOR
     * =============================================================
     */

    private void Capture_WireMessageObserved(
        RustWireMessageInfo message)
    {
        /*
         * Compact research log.
         */
        _rustMessageLogger.Log(
            message);


        if (RustEntityPositionParser.TryParse(
                message,
                out RustEntityPosition?
                    position) &&
            position != null)
        {
            /*
             * Server -> client:
             * normal entity position updates.
             */
            if (message.Direction ==
                "S2C")
            {
                _passiveEntities.Apply(
                    position);
            }

            /*
             * Experimental self detection.
             *
             * If Rust sends our own EntityPosition
             * from client -> server, this entity ID
             * should belong to us.
             */
            if (message.Direction ==
                "C2S")
            {
                if (_selfEntityId !=
                    position.EntityId)
                {
                    _selfEntityId =
                        position.EntityId;

                    _logQueue.Enqueue(
                        $"[PASSIVE] SELF candidate " +
                        $"id={position.EntityId} " +
                        $"xyz=({position.X:F2}, " +
                        $"{position.Y:F2}, " +
                        $"{position.Z:F2})");
                }

                /*
                 * Keep our own position in the same
                 * entity manager used by the radar.
                 */
                _passiveEntities.Apply(
                    position);
            }

            long sample =
                Interlocked.Increment(
                    ref _passiveUiSample);

            if ((sample % 50) == 0)
            {
                _logQueue.Enqueue(
                    $"[PASSIVE] POS " +
                    $"{message.Direction} " +
                    $"id={position.EntityId} " +
                    $"xyz=({position.X:F2}, " +
                    $"{position.Y:F2}, " +
                    $"{position.Z:F2}) " +
                    $"state={position.ProtectionState}");
            }
        }

        string protection;

        if (message.IsProtected)
        {
            string counter =
                message.Counter.HasValue
                    ? message.Counter.Value
                        .ToString()
                    : "?";


            protection =
                $"ENC " +
                $"state={message.ProtectionStateText,-4} " +
                $"body={message.ProtectedBodyLength,-4} " +
                $"ctr={counter,-8} " +
                $"{(message.DecryptionSucceeded ? "DEC" : "OPAQUE")}";


            /*
             * Only make anomalous counter states noisy.
             */
            if (message.CounterStatus is
                ProtectionCounterStatus.Gap or
                ProtectionCounterStatus.OutOfOrder or
                ProtectionCounterStatus.Duplicate)
            {
                protection +=
                    $" {message.CounterStatus}";

                if (message.CounterDelta.HasValue)
                {
                    protection +=
                        $"({message.CounterDelta.Value:+#;-#;0})";
                }
            }
        }
        else
        {
            protection =
                $"PLAIN body={message.BodyLength,-4}";
        }


        string line =
            $"{message.TimestampUtc.ToLocalTime():HH:mm:ss.fff} " +
            $"{message.Direction,-3} " +
            $"{message.Name,-16} " +
            $"raw=0x{message.RawType:X2} " +
            $"len={message.PacketLength,-5} " +
            $"{protection}";


        /*
         * EntityPosition shape classification.
         */
        if (message.Kind ==
            RustWireMessageKind.EntityPosition)
        {
            string shape =
                message.PositionShape switch
                {
                    RustPositionShape.Position36 =>
                        "POS36",

                    RustPositionShape.Position44 =>
                        "POS44",

                    RustPositionShape.Unexpected =>
                        "BADPOS",

                    _ =>
                        "-"
                };

            line +=
                $" shape={shape}";
        }


        /*
         * Don't print enormous message bodies to WPF.
         */
        if (!string.IsNullOrWhiteSpace(
                message.BodyPreviewHex))
        {
            line +=
                $" body={message.BodyPreviewHex}";
        }


        _logQueue.Enqueue(
            line);
    }


    private void Capture_StatusChanged(
        string status)
    {
        Dispatcher.BeginInvoke(
            () =>
            {
                StatusTextBlock.Text =
                    status;
            });
    }


    /*
     * =============================================================
     * RUST RELAY START
     * =============================================================
     */

    private async void StartRelayButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_relayServer.IsRunning)
            return;


        string url =
            RelayUrlTextBox.Text.Trim();

        string token =
            RelayTokenTextBox.Text.Trim();


        if (string.IsNullOrWhiteSpace(
                url))
        {
            MessageBox.Show(
                "Enter a relay listen URL.");

            return;
        }


        if (string.IsNullOrWhiteSpace(
                token))
        {
            MessageBox.Show(
                "Enter a relay authentication token.");

            return;
        }


        try
        {
            Interlocked.Exchange(
                ref _relayUiSample,
                0);


            _relayEntities.Clear();


            await _relayServer.StartAsync(
                url,
                token);


            StartRelayButton.IsEnabled =
                false;

            StopRelayButton.IsEnabled =
                true;


            RelayStatusText.Text =
                "LISTENING";


            StatusTextBlock.Text =
                $"RustRelay receiver listening on {url}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.ToString(),
                "Could not start RustRelay receiver",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    /*
     * =============================================================
     * RUST RELAY STOP
     * =============================================================
     */

    private async void StopRelayButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            await _relayServer.StopAsync();
        }
        catch (Exception ex)
        {
            _logQueue.Enqueue(
                $"[RELAY] Stop error: {ex.Message}");
        }


        StartRelayButton.IsEnabled =
            true;

        StopRelayButton.IsEnabled =
            false;


        RelayStatusText.Text =
            "STOPPED";
    }


    /*
     * =============================================================
     * RELAY STATUS
     * =============================================================
     */

    private void RelayServer_StatusChanged(
        string status)
    {
        _logQueue.Enqueue(
            $"[RELAY] {status}");


        Dispatcher.BeginInvoke(
            () =>
            {
                RelayStatusText.Text =
                    status;
            });
    }


    /*
     * =============================================================
     * RELAY PACKETS
     * =============================================================
     */

    private void RelayServer_PacketObserved(
        RelayPacketInfo packet)
    {
        /*
         * Destroy events are rare and useful,
         * so always show them.
         */
        if (packet.Destroy != null)
        {
            _logQueue.Enqueue(
                $"[RELAY] DESTROY " +
                $"id={packet.Destroy.EntityId} " +
                $"mode={packet.Destroy.Mode}");

            return;
        }


        /*
         * Position traffic can be huge.
         *
         * The entity manager still receives EVERY
         * position update. We only sample what gets
         * printed into WPF.
         */
        if (packet.Position != null)
        {
            long sample =
                Interlocked.Increment(
                    ref _relayUiSample);


            if ((sample % 50) != 0)
                return;


            RelayPosition p =
                packet.Position;


            _logQueue.Enqueue(
                $"[RELAY] POS " +
                $"id={p.EntityId} " +
                $"xyz=({p.X:F2}, {p.Y:F2}, {p.Z:F2}) " +
                $"rot=({p.RotationX:F2}, {p.RotationY:F2}, {p.RotationZ:F2}) " +
                $"parent={p.ParentId?.ToString() ?? "-"}");
        }
    }


    /*
     * =============================================================
     * UI TIMER
     * =============================================================
     */

    private void UiTimer_Tick(
        object? sender,
        EventArgs e)
    {
        /*
         * ---------------------------------------------------------
         * PASSIVE CAPTURE STATS
         * ---------------------------------------------------------
         */

        CaptureStatsSnapshot stats =
            _capture.GetStatistics();


        UdpCountText.Text =
            stats.UdpPackets.ToString("N0");

        RakNetCountText.Text =
            stats.RakNetFrames.ToString("N0");

        EntitiesCountText.Text =
            stats.Entities.ToString("N0");

        PositionsCountText.Text =
            stats.EntityPositions.ToString("N0");

        DestroyCountText.Text =
            stats.EntityDestroy.ToString("N0");

        RpcCountText.Text =
            stats.RpcMessages.ToString("N0");

        ProtectedCountText.Text =
            stats.ProtectedMessages.ToString("N0");

        IReadOnlyList<RustEntityState>
            passiveEntities =
                _passiveEntities.Snapshot(
                    TimeSpan.FromSeconds(
                        60));

        PlainEntityCountText.Text =
            passiveEntities.Count
                .ToString("N0");


        /*
         * ---------------------------------------------------------
         * RELAY RADAR
         * ---------------------------------------------------------
         *
         * For the first radar version we're interested
         * in things that are actively receiving position
         * packets.
         *
         * Old/stale coordinates are omitted.
         */

        IReadOnlyList<RelayEntityState>
            relayEntities =
                _relayEntities.Snapshot(
                    TimeSpan.FromSeconds(
                        10));


        /*
         * Passive capture is the preferred source now.
         *
         * When passive capture is running, show its
         * decoded coordinates even if the list happens
         * to be empty.
         *
         * Relay remains available as a fallback/test
         * source.
         */
        if (_capture.IsRunning ||
            passiveEntities.Count > 0)
        {
            RelayRadarControl.SetEntities(
                passiveEntities,
                "Passive XYZ",
                _selfEntityId);
        }
        else
        {
            RelayRadarControl.SetEntities(
                relayEntities,
                "Relay XYZ");
        }


        /*
         * ---------------------------------------------------------
         * RELAY STATS
         * ---------------------------------------------------------
         */

        RustRelayStatsSnapshot relayStats =
            _relayServer.GetStatistics();


        RelayPacketCountText.Text =
            relayStats.Packets.ToString("N0");

        RelayPositionCountText.Text =
            relayStats.Positions.ToString("N0");

        RelayEntityCountText.Text =
            relayEntities.Count.ToString("N0");


        /*
         * Periodically remove ancient entries from the
         * backing dictionary too.
         */
        if ((DateTime.UtcNow.Second % 10) == 0)
        {
            _relayEntities.PurgeOlderThan(
                TimeSpan.FromMinutes(
                    2));
        }


        /*
         * ---------------------------------------------------------
         * DRAIN UI LOG QUEUE
         * ---------------------------------------------------------
         */

        const int maximumPerTick =
            300;

        int added = 0;


        while (added <
               maximumPerTick &&
               _logQueue.TryDequeue(
                   out string? line))
        {
            PacketLogListBox.Items.Add(
                line);

            added++;
        }


        /*
         * Keep WPF from accumulating millions of
         * ListBox objects.
         */
        while (PacketLogListBox.Items.Count >
               3000)
        {
            PacketLogListBox.Items.RemoveAt(
                0);
        }


        if (added > 0 &&
            PacketLogListBox.Items.Count > 0)
        {
            PacketLogListBox.ScrollIntoView(
                PacketLogListBox.Items[
                    PacketLogListBox.Items.Count -
                    1]);
        }
    }


    /*
     * =============================================================
     * TEST MARKERS
     * =============================================================
     */

    private void MarkStill_Click(
        object sender,
        RoutedEventArgs e)
    {
        _fileLogger.LogMarker(
            "STILL_START");

        _rustMessageLogger.LogMarker(
            "STILL_START");


        _logQueue.Enqueue(
            "========== STILL_START ==========");
    }


    private void MarkWalk_Click(
        object sender,
        RoutedEventArgs e)
    {
        _fileLogger.LogMarker(
            "WALK_START");

        _rustMessageLogger.LogMarker(
            "WALK_START");


        _logQueue.Enqueue(
            "========== WALK_START ==========");
    }


    private void MarkStop_Click(
        object sender,
        RoutedEventArgs e)
    {
        _fileLogger.LogMarker(
            "WALK_END");

        _rustMessageLogger.LogMarker(
            "WALK_END");


        _logQueue.Enqueue(
            "========== WALK_END ==========");
    }


    /*
     * =============================================================
     * LAUNCH RUST
     * =============================================================
     */

    private void LaunchRustButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            Process.Start(
                new ProcessStartInfo
                {
                    FileName =
                        "steam://rungameid/252490",

                    UseShellExecute =
                        true
                });
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "Could not launch Rust");
        }
    }


    /*
     * =============================================================
     * WINDOW CLOSE
     * =============================================================
     */

    protected override void OnClosed(
        EventArgs e)
    {
        _uiTimer.Stop();


        try
        {
            _capture.Dispose();
        }
        catch
        {
        }


        try
        {
            _fileLogger.Dispose();
        }
        catch
        {
        }


        try
        {
            _rustMessageLogger.Dispose();
        }
        catch
        {
        }


        try
        {
            _relayServer.Dispose();
        }
        catch
        {
        }


        base.OnClosed(
            e);
    }
}