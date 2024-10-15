using System.Security.Cryptography;

namespace RFC6238
{
    public class TOTP
    {

        private static byte[] HmacSha(string crypto, byte[] keyBytes, byte[] text)
        {
            try
            {
                HMAC hmac;
                if (crypto == "HMACSHA256")
                {
                    hmac = new HMACSHA256(FixKeyLength(keyBytes, 32)); 
                }
                else if (crypto == "HMACSHA512")
                {
                    hmac = new HMACSHA512(FixKeyLength(keyBytes, 64)); 
                }
                else
                {
                    hmac = new HMACSHA1(FixKeyLength(keyBytes, 20)); 
                }

                return hmac.ComputeHash(text);
            }
            catch (CryptographicException cex)
            {
                throw new Exception("Error during HMAC generation", cex);
            }
        }

        private static byte[] FixKeyLength(byte[] keyBytes, int requiredLength)
        {
            if (keyBytes.Length == requiredLength)
            {
                return keyBytes;
            }

            byte[] fixedKey = new byte[requiredLength];
            if (keyBytes.Length < requiredLength)
            {
                // If key is too short, pad it with zeros
                Array.Copy(keyBytes, fixedKey, keyBytes.Length);
            }
            else
            {
                // If key is too long, truncate it
                Array.Copy(keyBytes, fixedKey, requiredLength);
            }

            return fixedKey;
        }

        private static byte[] HexStr2Bytes(string hex)
        {
            int len = hex.Length;
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2)
            {
                data[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return data;
        }

        private static readonly int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

        public static string GenerateTOTP(string key, string time, string returnDigits)
        {
            return GenerateTOTP(key, time, returnDigits, "HMACSHA1");
        }

        public static string GenerateTOTP256(string key, string time, string returnDigits)
        {
            return GenerateTOTP(key, time, returnDigits, "HMACSHA256");
        }

        //public static string GenerateTOTP512(string key, string time, string returnDigits)
        //{
        //    return GenerateTOTP(key, time, returnDigits, "HMACSHA512");
        //}

        public static string GenerateTOTP(string key, string time, string returnDigits, string crypto)
        {
            int codeDigits = int.Parse(returnDigits);
            string result = null;

            while (time.Length < 16)
                time = "0" + time;

            byte[] msg = HexStr2Bytes(time);
            byte[] k = HexStr2Bytes(key);
            byte[] hash = HmacSha(crypto, k, msg);

            int offset = hash[hash.Length - 1] & 0xf;

            int binary = ((hash[offset] & 0x7f) << 24) |
                         ((hash[offset + 1] & 0xff) << 16) |
                         ((hash[offset + 2] & 0xff) << 8) |
                         (hash[offset + 3] & 0xff);

            int otp = binary % DIGITS_POWER[codeDigits];

            result = otp.ToString();
            while (result.Length < codeDigits)
            {
                result = "0" + result;
            }
            return result;
        }

    }

}
