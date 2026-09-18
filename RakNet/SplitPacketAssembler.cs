namespace RustRadar.RakNet;

public sealed class SplitPacketAssembler
{
    private readonly object _sync = new();

    private readonly Dictionary<SplitKey, SplitGroup>
        _groups = new();

    private int _calls;

    public byte[]? Process(
        string flow,
        RakNetFrame frame)
    {
        if (!frame.IsSplit)
            return frame.Payload;

        if (frame.SplitCount == null ||
            frame.SplitId == null ||
            frame.SplitIndex == null)
        {
            return null;
        }

        var key = new SplitKey(
            flow,
            frame.SplitId.Value,
            frame.SplitCount.Value);

        lock (_sync)
        {
            if (!_groups.TryGetValue(
                    key,
                    out SplitGroup? group))
            {
                group = new SplitGroup(
                    frame.SplitCount.Value);

                _groups[key] = group;
            }

            group.LastSeenUtc =
                DateTime.UtcNow;

            uint index =
                frame.SplitIndex.Value;

            if (index >= group.Fragments.Length)
                return null;

            if (group.Fragments[index] == null)
            {
                group.Fragments[index] =
                    frame.Payload;

                group.Received++;
            }

            if (group.Received ==
                group.Fragments.Length)
            {
                int totalLength = 0;

                foreach (byte[]? fragment
                         in group.Fragments)
                {
                    if (fragment == null)
                        return null;

                    totalLength += fragment.Length;
                }

                byte[] assembled =
                    new byte[totalLength];

                int offset = 0;

                foreach (byte[] fragment
                         in group.Fragments!)
                {
                    Buffer.BlockCopy(
                        fragment,
                        0,
                        assembled,
                        offset,
                        fragment.Length);

                    offset += fragment.Length;
                }

                _groups.Remove(key);

                return assembled;
            }

            _calls++;

            if ((_calls % 500) == 0)
                CleanupExpired();

            return null;
        }
    }

    private void CleanupExpired()
    {
        DateTime cutoff =
            DateTime.UtcNow -
            TimeSpan.FromSeconds(30);

        SplitKey[] expired =
            _groups
                .Where(x =>
                    x.Value.LastSeenUtc < cutoff)
                .Select(x => x.Key)
                .ToArray();

        foreach (SplitKey key in expired)
            _groups.Remove(key);
    }

    private readonly record struct SplitKey(
        string Flow,
        ushort SplitId,
        uint SplitCount);

    private sealed class SplitGroup
    {
        public byte[]?[] Fragments { get; }

        public int Received { get; set; }

        public DateTime LastSeenUtc { get; set; }

        public SplitGroup(uint fragmentCount)
        {
            Fragments =
                new byte[checked((int)fragmentCount)][];

            LastSeenUtc =
                DateTime.UtcNow;
        }
    }
}