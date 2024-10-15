using System.Globalization;

namespace TOTP
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("");
            test();

            Console.WriteLine("");
            Console.WriteLine("Press Enter to exit");
            Console.ReadLine();
        }
        public static void test()
        {
            string seed = "3132333435363738393031323334353637383930";
            string seed32 = "31323334353637383930313233343536373839303132333435363738393031323334";
            //string seed64 = "31323334353637383930313233343536373839303132333435363738393031323334" +
            //                "31323334353637383930313233343536373839303132333435363738393031323334";
            long T0 = 0;
            long X = 30;
            long[] testTime = { 59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };

            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            Console.WriteLine("+-------------+---------------------+------------------+----------+--------+");
            Console.WriteLine("|  Time(sec)  |  Time (UTC format)  | Value of T(Hex)  |   TOTP   | Mode   |");
            Console.WriteLine("+-------------+---------------------+------------------+----------+--------+");

            foreach (long time in testTime)
            {
                long T = (time - T0) / X;
                string steps = T.ToString("X").PadLeft(16, '0');
                string utcTime = epoch.AddSeconds(time).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

                Console.WriteLine($"| {time,-11} | {utcTime} | {steps} | {RFC6238.TOTP.GenerateTOTP(seed, steps, "8")} | SHA1   |");
                Console.WriteLine($"| {time,-11} | {utcTime} | {steps} | {RFC6238.TOTP.GenerateTOTP256(seed32, steps, "8")} | SHA256 |");
                //Console.WriteLine($"| {time,-11} | {utcTime} | {steps} | {GenerateTOTP512(seed64, steps, "8")} | SHA512 |");
                Console.WriteLine("+-------------+---------------------+------------------+----------+--------+");
            }
        }

    }
}
