using System.Collections.Concurrent;
using RustRadar.Protocol;

namespace RustRadar.Models;

public sealed class RustEntityState
{
    public ulong Id { get; init; }

    public float X { get; set; }
    public float Y { get; set; }
    public float Z { get; set; }

    public float RotationX { get; set; }
    public float RotationY { get; set; }
    public float RotationZ { get; set; }

    public float NetworkTime { get; set; }

    public ulong? ParentId { get; set; }

    public bool WasProtected { get; set; }

    public RustProtectionState
        ProtectionState
    {
        get;
        set;
    }

    public DateTime LastSeenUtc
    {
        get;
        set;
    }
}

public sealed class EntityManager
{
    private readonly ConcurrentDictionary<
        ulong,
        RustEntityState> _entities =
            new();

    public int Count =>
        _entities.Count;

    public void Apply(
        RustEntityPosition position)
    {
        _entities.AddOrUpdate(
            position.EntityId,

            _ =>
                new RustEntityState
                {
                    Id =
                        position.EntityId,

                    X =
                        position.X,

                    Y =
                        position.Y,

                    Z =
                        position.Z,

                    RotationX =
                        position.RotationX,

                    RotationY =
                        position.RotationY,

                    RotationZ =
                        position.RotationZ,

                    NetworkTime =
                        position.NetworkTime,

                    ParentId =
                        position.ParentId,

                    WasProtected =
                        position.WasProtected,

                    ProtectionState =
                        position.ProtectionState,

                    LastSeenUtc =
                        position.TimestampUtc
                },

            (_, entity) =>
            {
                entity.X =
                    position.X;

                entity.Y =
                    position.Y;

                entity.Z =
                    position.Z;

                entity.RotationX =
                    position.RotationX;

                entity.RotationY =
                    position.RotationY;

                entity.RotationZ =
                    position.RotationZ;

                entity.NetworkTime =
                    position.NetworkTime;

                entity.ParentId =
                    position.ParentId;

                entity.WasProtected =
                    position.WasProtected;

                entity.ProtectionState =
                    position.ProtectionState;

                entity.LastSeenUtc =
                    position.TimestampUtc;

                return entity;
            });
    }

    public void Remove(
        ulong entityId)
    {
        _entities.TryRemove(
            entityId,
            out _);
    }

    public IReadOnlyList<RustEntityState>
        Snapshot()
    {
        return
            _entities.Values
                .ToList();
    }

    public IReadOnlyList<RustEntityState>
        Snapshot(
            TimeSpan maxAge)
    {
        DateTime cutoff =
            DateTime.UtcNow -
            maxAge;

        return
            _entities.Values
                .Where(
                    entity =>
                        entity.LastSeenUtc >=
                        cutoff)
                .ToList();
    }

    public void PurgeOlderThan(
        TimeSpan age)
    {
        DateTime cutoff =
            DateTime.UtcNow -
            age;

        foreach (KeyValuePair<
                     ulong,
                     RustEntityState> pair
                 in _entities)
        {
            if (pair.Value.LastSeenUtc <
                cutoff)
            {
                _entities.TryRemove(
                    pair.Key,
                    out _);
            }
        }
    }

    public void Clear()
    {
        _entities.Clear();
    }
}