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
    public class Fingerprint
    {
        public static bool VerifySig(String Encrypted, String PubKey, String signature)
        {
            IBuffer buffMsg = CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(Encrypted));
            IBuffer buffsig = CryptographicBuffer.DecodeFromBase64String(signature);

            IBuffer keyBuffer = CryptographicBuffer.DecodeFromBase64String(PubKey);
            AsymmetricKeyAlgorithmProvider provider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaSignPkcs1Sha256);
            CryptographicKey publicKey = provider.ImportPublicKey(keyBuffer, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);

            bool IsAuthenticated = CryptographicEngine.VerifySignature(publicKey, buffMsg, buffsig);
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
