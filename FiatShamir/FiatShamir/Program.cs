using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace FiatShamir
{
    /// <summary>
    /// This program is demostrating the Fiat-Shamir Identification Protocol.
    /// </summary>
    internal class Program
    {
        /// <summary>
        /// Generates a cryptographically secure random BigInteger within a specified range.
        /// </summary>
        /// <param name="minValue">The minimum value (inclusive) of the range.</param>
        /// <param name="maxValue">The maximum value (exclusive) of the range.</param>
        /// <returns>A randomly generated BigInteger in the specified range.</returns>
        static BigInteger SecureRandomBigInteger(BigInteger minValue, BigInteger maxValue)
        {
            // Create a cryptographically secure random number generator
            var random = new SecureRandom();

            // Calculate the range (maxValue - minValue)
            var range = maxValue.Subtract(minValue);

            // Generate a byte array to represent the random number in the range
            var bytes = range.ToByteArray();

            // Fill the byte array with secure random data
            random.NextBytes(bytes);

            // Convert the byte array to a BigInteger 
            var result = new BigInteger(bytes);

            // Ensure the result is non-negative and within the correct range
            return result.Abs().Mod(range).Add(minValue);
        }

        /// <summary>
        /// Generate a cryptographically secure prime number of the specified bit length.
        /// </summary>
        /// <param name="bits">The bit length of the prime number to generate.</param>
        /// <returns>A cryptographically secure prime number.</returns>
        static BigInteger GeneratePrime(int bits)
        {
            var random = new SecureRandom();
            BigInteger prime;
            do
            {
                // Generate a random BigInteger with the specified number of bits
                prime = new BigInteger(bits, random);
            }
            while (!prime.IsProbablePrime(50)); // Use a 50-round Miller-Rabin test for primality

            return prime;
        }

        /// <summary>
        /// Setup phase of the Fiat-Shamir Identification Protocol.
        /// Generates public parameters (n, y) and a secret (x) for the prover.
        /// </summary>
        /// <returns>
        /// A tuple containing:
        /// 1. The public modulus `n = p * q` where `p` and `q` are large primes.
        /// 2. The public value `y = x^2 mod n` where `x` is the secret.
        /// 3. The prover's secret key `x`.
        /// </returns>
        static (BigInteger n, BigInteger y, BigInteger x) Setup()
        {
            // Generate two large prime numbers p and q
            var p = GeneratePrime(128);  // Prime p of 128 bits
            var q = GeneratePrime(128);  // Prime q of 128 bits

            // Compute n = p * q
            var n = p.Multiply(q);

            // Generate a random secret x such that 1 <= x <= n-1
            var x = SecureRandomBigInteger(BigInteger.One, n.Subtract(BigInteger.One));

            // Compute the public value y = x^2 mod n
            var y = x.ModPow(BigInteger.Two, n); // y = x^2 mod n

            // Return the public key (n, y) and the secret (x)
            return (n, y, x);
        }

        /// <summary>
        /// Prover's commitment step of the Fiat-Shamir Identification Protocol.
        /// Prover generates a random commitment `t` to their secret `x`.
        /// </summary>
        /// <param name="n">The public modulus `n = p * q`.</param>
        /// <returns>
        /// A tuple containing:
        /// 1. The commitment `t = r^2 mod n` where `r` is a random value.
        /// 2. The random value `r` used in the commitment calculation.
        /// </returns>
        static (BigInteger t, BigInteger r) ProverCommitment(BigInteger n)
        {
            // Prover selects a random r such that 1 <= r <= n-1
            var r = SecureRandomBigInteger(BigInteger.One, n.Subtract(BigInteger.One));

            // Compute commitment t = r^2 mod n
            var t = r.ModPow(BigInteger.Two, n);

            // Return the commitment t and the random value r
            return (t, r);
        }

        /// <summary>
        /// Verifier's challenge phase. Verifier sends a random challenge (either 0 or 1).
        /// </summary>
        /// <returns>
        /// A random challenge `c`, either 0 or 1.
        /// </returns>
        static int VerifierChallenge()
        {
            // Create a new cryptographically secure random number generator
            var random = new SecureRandom();

            // Generate a random challenge bit (either 0 or 1)
            return random.Next(0, 2); // Challenge is either 0 or 1
        }

        /// <summary>
        /// Prover's response phase. Prover computes the response based on the challenge `c`.
        /// </summary>
        /// <param name="r">The random value `r` from the commitment phase.</param>
        /// <param name="x">The prover's secret `x`.</param>
        /// <param name="c">The challenge `c` from the verifier (either 0 or 1).</param>
        /// <param name="n">The public modulus `n = p * q`.</param>
        /// <returns>The response `s`, which is either `r` or `r * x^c mod n` depending on the challenge.</returns>
        static BigInteger ProverResponse(BigInteger r, BigInteger x, int c, BigInteger n)
        {
            // Prover calculates s = r * x^c mod n
            return r.Multiply(x.ModPow(BigInteger.ValueOf(c), n)).Mod(n);
            /*
             Note that:
                  Actually we calculate: (r*(x^c mod n)) mod n
            Why?
             For big numbers, the two modulus operations help prevent overflow 
             and ensure that the result remains within the correct bounds.
             */
        }

        /// <summary>
        /// Verifier checks the prover's response using the challenge and commitment.
        /// </summary>
        /// <param name="s">The prover's response.</param>
        /// <param name="t">The commitment `t` from the prover.</param>
        /// <param name="y">The public value `y = x^2 mod n`.</param>
        /// <param name="c">The challenge `c` from the verifier (either 0 or 1).</param>
        /// <param name="n">The public modulus `n = p * q`.</param>
        /// <returns>True if the response is valid, false otherwise.</returns>
        static bool VerifierCheck(BigInteger s, BigInteger t, BigInteger y, int c, BigInteger n)
        {
            // Verifier checks if s^2 = t * y^c mod n
            var left = s.ModPow(BigInteger.Two, n);
            var right = t.Multiply(y.ModPow(BigInteger.ValueOf(c), n)).Mod(n);
            return left.Equals(right);
        }



        /// <summary>
        /// Main method to run the Fiat-Shamir Identification Protocol.
        /// It simulates the interaction between the prover and the verifier.
        /// </summary>
        public static void Main()
        {
            // Setup phase: Generate public parameters (n, y) and secret (x)
            var (n, y, x) = Setup();
            Console.WriteLine("Public key:");
            Console.WriteLine($"n = {n}");
            Console.WriteLine($"y = {y}");


            /*k is the number of rounds to repeat the protocol.
             It is good to set k to 10-20 round.
             More than 20 round can significantly increase the runtime, while the security
             will increase less-and-less with every round.*/

            int k = 10; 
            bool isValid = true;

            // Run the protocol for k rounds
            for (int i = 0; i < k; i++)
            {
                Console.WriteLine($"\nRound {i + 1} of {k}:");

                // Prover generates commitment t to their secret (x)
                var (t, r) = ProverCommitment(n);
                Console.WriteLine($"Prover's commitment: t = {t}");

                // Verifier sends a random challenge (either 0 or 1)
                var c = VerifierChallenge();
                Console.WriteLine($"Verifier's challenge: c = {c}");

                // Prover responds to the challenge
                var s = ProverResponse(r, x, c, n);
                Console.WriteLine($"Prover's response: s = {s}");

                // Verifier checks the prover's response
                if (!VerifierCheck(s, t, y, c, n))
                {
                    Console.WriteLine("Verification failed at round " + (i + 1));
                    isValid = false;
                    break; // Abort the protocol if any round fails
                }
                else
                {
                    Console.WriteLine("Verification successful at round " + (i + 1));
                }
            }

            // Final result
            if (isValid)
                Console.WriteLine("\nThe prover successfully completed all rounds!");
            else
                Console.WriteLine("\nThe prover failed in one or more rounds.");

        }

    }
}
