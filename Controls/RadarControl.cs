using System.Globalization;
using System.Windows;
using System.Windows.Media;
using RustRadar.Models;

namespace RustRadar.Controls;

public sealed class RadarControl :
    FrameworkElement
{
    private sealed record RadarPoint(
        ulong Id,
        float X,
        float Z);

    private IReadOnlyList<RadarPoint>
        _entities =
            Array.Empty<RadarPoint>();

    private string _sourceLabel =
        "XYZ";

    public RadarControl()
    {
        SnapsToDevicePixels =
            true;
    }

    public void SetEntities(
        IReadOnlyList<RustEntityState> entities,
        string sourceLabel =
            "Passive decoded XYZ")
    {
        _sourceLabel =
            sourceLabel;

        _entities =
            entities
                .Select(
                    entity =>
                        new RadarPoint(
                            entity.Id,
                            entity.X,
                            entity.Z))
                .ToList();

        InvalidateVisual();
    }

    public void SetEntities(
        IReadOnlyList<RelayEntityState> entities,
        string sourceLabel =
            "Relay XYZ")
    {
        _sourceLabel =
            sourceLabel;

        _entities =
            entities
                .Select(
                    entity =>
                        new RadarPoint(
                            entity.EntityId,
                            entity.X,
                            entity.Z))
                .ToList();

        InvalidateVisual();
    }

    protected override void OnRender(
        DrawingContext dc)
    {
        base.OnRender(dc);

        double width =
            ActualWidth;

        double height =
            ActualHeight;

        dc.DrawRectangle(
            Brushes.Black,
            null,
            new Rect(
                0,
                0,
                width,
                height));

        DrawGrid(
            dc,
            width,
            height);

        if (_entities.Count == 0)
        {
            DrawText(
                dc,
                $"Waiting for {_sourceLabel}...",
                15,
                15,
                Brushes.Gray);

            return;
        }

        float minX =
            _entities.Min(e => e.X);

        float maxX =
            _entities.Max(e => e.X);

        float minZ =
            _entities.Min(e => e.Z);

        float maxZ =
            _entities.Max(e => e.Z);

        if (maxX - minX < 10)
        {
            float center =
                (maxX + minX) / 2f;

            minX =
                center - 5;

            maxX =
                center + 5;
        }

        if (maxZ - minZ < 10)
        {
            float center =
                (maxZ + minZ) / 2f;

            minZ =
                center - 5;

            maxZ =
                center + 5;
        }

        const double padding =
            30;

        double availableWidth =
            Math.Max(
                1,
                width -
                padding * 2);

        double availableHeight =
            Math.Max(
                1,
                height -
                padding * 2);

        foreach (RadarPoint entity
                 in _entities)
        {
            double normalizedX =
                (entity.X - minX) /
                (maxX - minX);

            double normalizedZ =
                (entity.Z - minZ) /
                (maxZ - minZ);

            double px =
                padding +
                normalizedX *
                availableWidth;

            double py =
                padding +
                (1.0 -
                 normalizedZ) *
                availableHeight;

            dc.DrawEllipse(
                Brushes.Red,
                null,
                new Point(
                    px,
                    py),
                3,
                3);
        }

        DrawText(
            dc,
            $"{_sourceLabel}: {_entities.Count:N0}",
            12,
            10,
            Brushes.White);

        DrawText(
            dc,
            $"X {minX:F1} → {maxX:F1}",
            12,
            30,
            Brushes.Gray);

        DrawText(
            dc,
            $"Z {minZ:F1} → {maxZ:F1}",
            12,
            48,
            Brushes.Gray);
    }

    private static void DrawGrid(
        DrawingContext dc,
        double width,
        double height)
    {
        Pen gridPen =
            new(
                new SolidColorBrush(
                    Color.FromRgb(
                        40,
                        40,
                        40)),
                1);

        for (int i = 1;
             i < 10;
             i++)
        {
            double x =
                width *
                i /
                10.0;

            double y =
                height *
                i /
                10.0;

            dc.DrawLine(
                gridPen,
                new Point(x, 0),
                new Point(x, height));

            dc.DrawLine(
                gridPen,
                new Point(0, y),
                new Point(width, y));
        }
    }

    private static void DrawText(
        DrawingContext dc,
        string text,
        double x,
        double y,
        Brush brush)
    {
        var formatted =
            new FormattedText(
                text,
                CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight,
                new Typeface("Consolas"),
                12,
                brush,
                1.0);

        dc.DrawText(
            formatted,
            new Point(
                x,
                y));
    }
}