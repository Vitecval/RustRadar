using System.Collections.Concurrent;

namespace RustRadar.Models;
using RustRadar.Relay;

public sealed record RelayEntityState(
    ulong EntityId,

    float X,
    float Y,
    float Z,

    float RotationX,
    float RotationY,
    float RotationZ,

    float NetworkTime,

    ulong? ParentId,

    DateTime LastUpdatedUtc,

    long? ServerTime);

public sealed class RelayEntityManager
{
    private readonly ConcurrentDictionary<
        ulong,
        RelayEntityState> _entities =
            new();

    public int Count =>
        _entities.Count;

    public void ApplyPosition(
        RelayPosition position,
        long? serverTime)
    {
        var state =
            new RelayEntityState(
                position.EntityId,

                position.X,
                position.Y,
                position.Z,

                position.RotationX,
                position.RotationY,
                position.RotationZ,

                position.NetworkTime,

                position.ParentId,

                DateTime.UtcNow,

                serverTime);

        _entities[position.EntityId] =
            state;
    }

    public void Remove(
        ulong entityId)
    {
        _entities.TryRemove(
            entityId,
            out _);
    }

    public IReadOnlyList<RelayEntityState>
        Snapshot(
            TimeSpan? maximumAge = null)
    {
        DateTime now =
            DateTime.UtcNow;

        IEnumerable<RelayEntityState> query =
            _entities.Values;

        if (maximumAge.HasValue)
        {
            TimeSpan age =
                maximumAge.Value;

            query =
                query.Where(
                    entity =>
                        now -
                        entity.LastUpdatedUtc
                        <= age);
        }

        return query
            .OrderBy(
                x => x.EntityId)
            .ToList();
    }

    public int PurgeOlderThan(
        TimeSpan age)
    {
        DateTime threshold =
            DateTime.UtcNow - age;

        int removed = 0;

        foreach (var pair
                 in _entities)
        {
            if (pair.Value.LastUpdatedUtc >=
                threshold)
            {
                continue;
            }

            if (_entities.TryRemove(
                    pair.Key,
                    out _))
            {
                removed++;
            }
        }

        return removed;
    }

    public void Clear()
    {
        _entities.Clear();
    }
}