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

    private ulong?
        _centerEntityId;

    private string _sourceLabel =
        "XYZ";

    /*
     * 500 Rust world units across.
     *
     * With a 500x500 pixel control:
     *
     * 1 pixel ~= 1 world meter/unit.
     */
    public double WorldSpan
    {
        get;
        set;
    } = 500.0;

    public RadarControl()
    {
        SnapsToDevicePixels =
            true;
    }

    public void SetEntities(
        IReadOnlyList<RustEntityState> entities,
        string sourceLabel =
            "Passive decoded XYZ",
        ulong? centerEntityId =
            null)
    {
        _sourceLabel =
            sourceLabel;

        _centerEntityId =
            centerEntityId;

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
            "Relay XYZ",
        ulong? centerEntityId =
            null)
    {
        _sourceLabel =
            sourceLabel;

        _centerEntityId =
            centerEntityId;

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

        if (width <= 1 ||
            height <= 1)
        {
            return;
        }

        DrawGrid(
            dc,
            width,
            height);

        double screenCenterX =
            width / 2.0;

        double screenCenterY =
            height / 2.0;

        /*
         * Always draw the radar center.
         */
        Pen centerPen =
            new(
                Brushes.DimGray,
                1);

        dc.DrawLine(
            centerPen,
            new Point(
                screenCenterX - 8,
                screenCenterY),
            new Point(
                screenCenterX + 8,
                screenCenterY));

        dc.DrawLine(
            centerPen,
            new Point(
                screenCenterX,
                screenCenterY - 8),
            new Point(
                screenCenterX,
                screenCenterY + 8));

        if (_entities.Count == 0)
        {
            DrawText(
                dc,
                $"Waiting for {_sourceLabel}...",
                12,
                10,
                Brushes.Gray);

            return;
        }

        RadarPoint? centerEntity =
            null;

        if (_centerEntityId.HasValue)
        {
            centerEntity =
                _entities.FirstOrDefault(
                    entity =>
                        entity.Id ==
                        _centerEntityId.Value);
        }

        /*
         * Until we positively identify ourselves,
         * use the average point only so the radar
         * remains useful.
         *
         * The text makes clear that this is NOT yet
         * a true player-centered radar.
         */
        float centerWorldX;
        float centerWorldZ;

        bool selfKnown =
            centerEntity != null;

        if (centerEntity != null)
        {
            centerWorldX =
                centerEntity.X;

            centerWorldZ =
                centerEntity.Z;
        }
        else
        {
            centerWorldX =
                _entities.Average(
                    entity => entity.X);

            centerWorldZ =
                _entities.Average(
                    entity => entity.Z);
        }

        double usableSize =
            Math.Min(
                width,
                height);

        double worldSpan =
            Math.Max(
                1.0,
                WorldSpan);

        double pixelsPerWorldUnit =
            usableSize /
            worldSpan;

        double halfWorld =
            worldSpan /
            2.0;

        int visibleEntities =
            0;

        foreach (RadarPoint entity
                 in _entities)
        {
            double dx =
                entity.X -
                centerWorldX;

            double dz =
                entity.Z -
                centerWorldZ;

            /*
             * Outside the visible 500x500 area.
             */
            if (Math.Abs(dx) >
                    halfWorld ||
                Math.Abs(dz) >
                    halfWorld)
            {
                continue;
            }

            double px =
                screenCenterX +
                dx *
                pixelsPerWorldUnit;

            /*
             * World +Z is upward on screen.
             */
            double py =
                screenCenterY -
                dz *
                pixelsPerWorldUnit;

            bool isSelf =
                selfKnown &&
                entity.Id ==
                centerEntity!.Id;

            if (isSelf)
            {
                dc.DrawEllipse(
                    Brushes.LimeGreen,
                    new Pen(
                        Brushes.White,
                        1),
                    new Point(
                        px,
                        py),
                    6,
                    6);
            }
            else
            {
                dc.DrawEllipse(
                    Brushes.Red,
                    null,
                    new Point(
                        px,
                        py),
                    3,
                    3);
            }

            visibleEntities++;
        }

        DrawText(
            dc,
            $"{_sourceLabel}: {visibleEntities:N0}/{_entities.Count:N0}",
            12,
            10,
            Brushes.White);

        DrawText(
            dc,
            $"View: {worldSpan:F0} x {worldSpan:F0}",
            12,
            28,
            Brushes.Gray);

        DrawText(
            dc,
            $"Center: X={centerWorldX:F1} Z={centerWorldZ:F1}",
            12,
            46,
            Brushes.Gray);

        if (selfKnown)
        {
            DrawText(
                dc,
                $"SELF: {centerEntity!.Id}",
                12,
                64,
                Brushes.LimeGreen);
        }
        else
        {
            DrawText(
                dc,
                "SELF NOT IDENTIFIED - temporary average center",
                12,
                64,
                Brushes.Orange);
        }
    }

    private void DrawGrid(
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

        /*
         * 10x10 grid.
         *
         * With WorldSpan=500 this means
         * each square is 50x50.
         */
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
                new Point(
                    x,
                    0),
                new Point(
                    x,
                    height));

            dc.DrawLine(
                gridPen,
                new Point(
                    0,
                    y),
                new Point(
                    width,
                    y));
        }

        /*
         * Make the exact center stronger.
         */
        Pen middlePen =
            new(
                new SolidColorBrush(
                    Color.FromRgb(
                        75,
                        75,
                        75)),
                1);

        dc.DrawLine(
            middlePen,
            new Point(
                width / 2,
                0),
            new Point(
                width / 2,
                height));

        dc.DrawLine(
            middlePen,
            new Point(
                0,
                height / 2),
            new Point(
                width,
                height / 2));
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
                new Typeface(
                    "Consolas"),
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