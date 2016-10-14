using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace SecureUWPClient.Ciphers.RSA
{
    public static class Fingerprint
    {
        public static bool VerifySignature(String encrypted, CryptographicKey hmacKey, String signature)
        {
            IBuffer buffMsg = CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(encrypted));
            IBuffer buffsig = CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(signature));
            Boolean IsAuthenticated = CryptographicEngine.VerifySignature(hmacKey, buffMsg, buffsig);
            if (!IsAuthenticated)
            {
                Debug.WriteLine("The Integrity of RSA cannot be verified.");
                return false;
            }
            else
            {
                Debug.WriteLine("The Integrity of RSA verified succesful");
                return true;
            }
        }
    }
}
