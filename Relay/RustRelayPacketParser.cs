using System.Buffers.Binary;

namespace RustRadar.Relay
{
    public sealed record RelayPosition(
        ulong EntityId,

        float X,
        float Y,
        float Z,

        float RotationX,
        float RotationY,
        float RotationZ,

        float NetworkTime,

        ulong? ParentId);


    public sealed record RelayDestroy(
        ulong EntityId,
        byte Mode);


    public sealed record RelayPacketInfo(
        DateTime ReceivedUtc,

        string WipeId,
        long? ServerTime,

        byte RawType,
        int TypeId,

        string Name,

        int PacketLength,

        RelayPosition? Position,

        RelayDestroy? Destroy);


    public static class RustRelayPacketParser
    {
        /*
         * Rust application messages are RakNet's
         * message id + 140.
         */
        public const byte RakNetMaximumType =
            140;


        public static RelayPacketInfo? Parse(
            ReadOnlySpan<byte> packet,
            string wipeId,
            long? serverTime)
        {
            if (packet.Length == 0)
                return null;


            byte rawType =
                packet[0];


            /*
             * Ignore RakNet's internal packet IDs.
             */
            if (rawType <=
                RakNetMaximumType)
            {
                return null;
            }


            int typeId =
                rawType -
                RakNetMaximumType;


            string name =
                GetMessageName(
                    typeId);


            ReadOnlySpan<byte> body =
                packet[1..];


            RelayPosition? position =
                null;

            RelayDestroy? destroy =
                null;


            switch (typeId)
            {
                /*
                 * =================================================
                 * EntityDestroy
                 *
                 * uint64 entityId
                 * byte destroyMode
                 * =================================================
                 */
                case 6:
                    {
                        if (body.Length >= 9)
                        {
                            ulong id =
                                BinaryPrimitives
                                    .ReadUInt64LittleEndian(
                                        body[..8]);


                            byte mode =
                                body[8];


                            destroy =
                                new RelayDestroy(
                                    id,
                                    mode);
                        }


                        break;
                    }


                /*
                 * =================================================
                 * EntityPosition
                 *
                 * uint64 entityId
                 *
                 * float x
                 * float y
                 * float z
                 *
                 * float rotX
                 * float rotY
                 * float rotZ
                 *
                 * float networkTime
                 *
                 * optional:
                 *
                 * uint64 parentId
                 *
                 *
                 * 36 bytes without parent
                 * 44 bytes with parent
                 * =================================================
                 */
                case 10:
                    {
                        position =
                            TryParsePosition(
                                body);

                        break;
                    }
            }


            return new RelayPacketInfo(
                DateTime.UtcNow,

                wipeId,
                serverTime,

                rawType,
                typeId,

                name,

                packet.Length,

                position,

                destroy);
        }


        private static RelayPosition?
            TryParsePosition(
                ReadOnlySpan<byte> body)
        {
            if (body.Length != 36 &&
                body.Length != 44)
            {
                return null;
            }


            ulong id =
                BinaryPrimitives
                    .ReadUInt64LittleEndian(
                        body.Slice(
                            0,
                            8));


            float x =
                BinaryPrimitives
                    .ReadSingleLittleEndian(
                        body.Slice(
                            8,
                            4));


            float y =
                BinaryPrimitives
                    .ReadSingleLittleEndian(
                        body.Slice(
                            12,
                            4));


            float z =
                BinaryPrimitives
                    .ReadSingleLittleEndian(
                        body.Slice(
                            16,
                            4));


            float rotX =
                BinaryPrimitives
                    .ReadSingleLittleEndian(
                        body.Slice(
                            20,
                            4));


            float rotY =
                BinaryPrimitives
                    .ReadSingleLittleEndian(
                        body.Slice(
                            24,
                            4));


            float rotZ =
                BinaryPrimitives
                    .ReadSingleLittleEndian(
                        body.Slice(
                            28,
                            4));


            float networkTime =
                BinaryPrimitives
                    .ReadSingleLittleEndian(
                        body.Slice(
                            32,
                            4));


            /*
             * Reject invalid floating point values before
             * allowing them into the radar.
             */
            if (!float.IsFinite(x) ||
                !float.IsFinite(y) ||
                !float.IsFinite(z) ||
                !float.IsFinite(rotX) ||
                !float.IsFinite(rotY) ||
                !float.IsFinite(rotZ) ||
                !float.IsFinite(networkTime))
            {
                return null;
            }


            ulong? parentId =
                null;


            if (body.Length == 44)
            {
                parentId =
                    BinaryPrimitives
                        .ReadUInt64LittleEndian(
                            body.Slice(
                                36,
                                8));
            }


            return new RelayPosition(
                id,

                x,
                y,
                z,

                rotX,
                rotY,
                rotZ,

                networkTime,

                parentId);
        }


        private static string GetMessageName(
            int typeId)
        {
            return typeId switch
            {
                1 =>
                    "Welcome",

                2 =>
                    "Auth",

                3 =>
                    "Approved",

                4 =>
                    "Ready",

                5 =>
                    "Entities",

                6 =>
                    "EntityDestroy",

                7 =>
                    "GroupChange",

                8 =>
                    "GroupDestroy",

                9 =>
                    "RPCMessage",

                10 =>
                    "EntityPosition",

                11 =>
                    "ConsoleMessage",

                12 =>
                    "ConsoleCommand",

                13 =>
                    "Effect",

                14 =>
                    "DisconnectReason",

                15 =>
                    "Tick",

                16 =>
                    "Message",

                17 =>
                    "RequestUserInformation",

                18 =>
                    "GiveUserInformation",

                19 =>
                    "GroupEnter",

                20 =>
                    "GroupLeave",

                21 =>
                    "VoiceData",

                22 =>
                    "EAC",

                23 =>
                    "EntityFlags",

                24 =>
                    "World",

                25 =>
                    "ConsoleReplicatedVars",

                26 =>
                    "QueueUpdate",

                27 =>
                    "SyncVar",

                28 =>
                    "PackedSyncVar",

                _ =>
                    $"Message{typeId}"
            };
        }
    }
}