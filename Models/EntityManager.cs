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

    public DateTime LastSeenUtc { get; set; }
}

public sealed class EntityManager
{
    private readonly ConcurrentDictionary<
        ulong,
        RustEntityState> _entities = new();

    public int Count =>
        _entities.Count;

    public void Apply(
        RustMessageInfo message)
    {
        if (message.Position is RustPosition pos)
        {
            _entities.AddOrUpdate(
                pos.EntityId,

                _ => new RustEntityState
                {
                    Id = pos.EntityId,

                    X = pos.X,
                    Y = pos.Y,
                    Z = pos.Z,

                    RotationX = pos.RotationX,
                    RotationY = pos.RotationY,
                    RotationZ = pos.RotationZ,

                    LastSeenUtc =
                        DateTime.UtcNow
                },

                (_, entity) =>
                {
                    entity.X = pos.X;
                    entity.Y = pos.Y;
                    entity.Z = pos.Z;

                    entity.RotationX =
                        pos.RotationX;

                    entity.RotationY =
                        pos.RotationY;

                    entity.RotationZ =
                        pos.RotationZ;

                    entity.LastSeenUtc =
                        DateTime.UtcNow;

                    return entity;
                });
        }

        if (message.DestroyedEntityId
            is ulong destroyed)
        {
            _entities.TryRemove(
                destroyed,
                out _);
        }
    }

    public IReadOnlyList<RustEntityState>
        Snapshot()
    {
        return _entities.Values.ToList();
    }

    public void Clear()
    {
        _entities.Clear();
    }
}