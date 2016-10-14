using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using SecureUWPChannel.Prooperties;

namespace SecureUWPClient.Configuration
{
    public class PrimeNumberGenerator
    {

        private BigInteger publicPrimeNumber;
        private BigInteger privatePrimeNumber;
        private int seed = 34;
        private BigInteger g, p;

        public BigInteger ClientPrimeNumber
        {
            get { return publicPrimeNumber; }
            set { publicPrimeNumber = value; }
        }

        public PrimeNumberGenerator()
        {
            g = BigInteger.Parse(SampleConfiguration.exponent);
            p = BigInteger.Parse(SampleConfiguration.modulus);
        }

        public String GetClientPublicNumber()
        {

            do
            {
                Random random = new Random();
                byte[] bytes = new byte[256 / 8];
                random.NextBytes(bytes);
                privatePrimeNumber = new BigInteger(bytes);
            }
            while (privatePrimeNumber < 0);

            publicPrimeNumber = BigInteger.ModPow(g, privatePrimeNumber, p);
            return publicPrimeNumber.ToString();
        }

        public String SessionDHGenerator(String ServerResult)
        {
            BigInteger exponent = BigInteger.Parse(ServerResult);
            BigInteger DHresult = BigInteger.ModPow(exponent, privatePrimeNumber, p);
            return DHresult.ToString();
        }

        public String pseudorandom()
        {
            seed++;
            double num = Math.Sin(seed) * (0.5);
            return num.ToString("G16");
        }
    }
 }
