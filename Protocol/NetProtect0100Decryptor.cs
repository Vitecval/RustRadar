using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RustRadar.Protocol;

public static class NetProtect0100Decryptor
{
    public const int KeyLength = 32;
    public const int NonceLength = 12;
    public const int TagLength = 16;

    private static readonly byte[] Key =
    [
        0x70, 0x74, 0x8D, 0xB6,
        0x43, 0x9E, 0x4E, 0x4C,
        0x36, 0xEF, 0x91, 0xD4,
        0x3D, 0x37, 0x45, 0x73,
        0x4A, 0x51, 0x42, 0xB7,
        0xB9, 0x3B, 0xEB, 0xE1,
        0x0B, 0xA3, 0x67, 0xA1,
        0xEA, 0xC7, 0x35, 0x3A
    ];

    public static bool TryDecrypt(
        ReadOnlySpan<byte> ciphertext,
        uint counter,
        ReadOnlySpan<byte> authenticationTag,
        out byte[] plaintext)
    {
        plaintext =
            Array.Empty<byte>();

        if (ciphertext.Length == 0)
            return false;

        if (authenticationTag.Length !=
            TagLength)
        {
            return false;
        }

        byte[] output =
            new byte[ciphertext.Length];

        Span<byte> nonce =
            stackalloc byte[NonceLength];

        /*
         * Observed 01 00 nonce:
         *
         * uint64(counter) LE
         * uint32(1)       LE
         */
        BinaryPrimitives.WriteUInt64LittleEndian(
            nonce[..8],
            counter);

        BinaryPrimitives.WriteUInt32LittleEndian(
            nonce[8..12],
            1);

        try
        {
            using AesGcm aes =
                new(
                    Key,
                    TagLength);

            aes.Decrypt(
                nonce,
                ciphertext,
                authenticationTag,
                output);

            plaintext =
                output;

            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static bool SelfTest(
        out string result)
    {
        byte[] ciphertext =
            Convert.FromHexString(
                "AE50376B576320C45D6C914A5F0256F7" +
                "AA03BCAE27865A591694BF1E7F5FEF34" +
                "3998C149");

        byte[] tag =
            Convert.FromHexString(
                "C27F9CC42E245424974FEF62D2F089DC");

        byte[] expected =
            Convert.FromHexString(
                "5E36000000000000" +
                "BF037042" +
                "3B671741" +
                "95BDBE41" +
                "00000080" +
                "672AE342" +
                "00000080" +
                "88EFAF44");

        if (!TryDecrypt(
                ciphertext,
                3829,
                tag,
                out byte[] plaintext))
        {
            result =
                "01 00 self-test: authentication FAILED.";

            return false;
        }

        if (!plaintext.AsSpan()
                .SequenceEqual(expected))
        {
            result =
                "01 00 self-test: plaintext mismatch.";

            return false;
        }

        result =
            "01 00 AES-GCM self-test PASSED.";

        return true;
    }
}