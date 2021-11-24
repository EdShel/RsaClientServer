using System.Numerics;

namespace RsaCommunication
{
    public record RsaKeyPair(RsaPublicKey publicKey, RsaPrivateKey privateKey);

    public record RsaPublicKey(BigInteger e, BigInteger n);
    public record RsaPrivateKey(BigInteger d, BigInteger n);

    public static class Rsa
    {
        public static RsaKeyPair GenerateKeys(int keyLengthBits)
        {
            var rng = new RandomBigIntegerGenerator();
            BigInteger p, q;
            do
            {
                p = rng.NextPrimeNumber(keyLengthBits);
                q = rng.NextPrimeNumber(keyLengthBits);
            } while (p == q);

            BigInteger n = p * q;

            BigInteger eulerTotientFunctionValue = (p - 1) * (q - 1);

            BigInteger e;
            do
            {
                for (e = rng.NextPrimeNumber(keyLengthBits);
                    BigInteger.GreatestCommonDivisor(eulerTotientFunctionValue, e) != 1;
                    e += 2) { }
            } while (e >= eulerTotientFunctionValue);

            BigInteger d = e.ModInverse(eulerTotientFunctionValue);

            return new RsaKeyPair(
                publicKey: new RsaPublicKey(e, n),
                privateKey: new RsaPrivateKey(d, n)
            );
        }

        public static byte[] Encrypt(byte[] plaintext, RsaPublicKey publicKey)
        {
            var (e, n) = publicKey;
            BigInteger plaintextNumber = new BigInteger(plaintext, true, true);
            BigInteger ciphertextNumber = BigInteger.ModPow(plaintextNumber, e, n);
            return ciphertextNumber.ToByteArray(true, true);
        }

        public static byte[] Decrypt(byte[] ciphertext, RsaPrivateKey privateKey)
        {
            var (d, n) = privateKey;
            BigInteger ciphertextNumber = new BigInteger(ciphertext, true, true);
            BigInteger plaintextNumber = BigInteger.ModPow(ciphertextNumber, d, n);
            return plaintextNumber.ToByteArray(true, true);
        }
    }

    public static class BigIntegerExtension
    {
        public static BigInteger ModInverse(this BigInteger value, BigInteger modulo)
        {
            //return BigInteger.ModPow(a, n - 2, n);

            BigInteger x, y;

            if (1 != GreatestCommonDivisorExtended(value, modulo, out x, out y))
                throw new ArgumentException("Invalid modulo", "modulo");

            if (x < 0)
                x += modulo;

            return x % modulo;
        }

        public static BigInteger GreatestCommonDivisorExtended(
            BigInteger left,
            BigInteger right,
            out BigInteger leftFactor,
            out BigInteger rightFactor)
        {
            leftFactor = 0;
            rightFactor = 1;
            BigInteger u = 1;
            BigInteger v = 0;
            BigInteger gcd = 0;

            while (left != 0)
            {
                BigInteger q = right / left;
                BigInteger r = right % left;

                BigInteger m = leftFactor - u * q;
                BigInteger n = rightFactor - v * q;

                right = left;
                left = r;
                leftFactor = u;
                rightFactor = v;
                u = m;
                v = n;

                gcd = right;
            }

            return gcd;
        }
    }
}
