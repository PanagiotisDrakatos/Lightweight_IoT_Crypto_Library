
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
    public class RSA_PKCS1:RsaCiphers
    {
        public async Task<String> RsaEncrypt(String Pubkey, String plainText)
        {
            try
            {
                IBuffer keyBuffer = CryptographicBuffer.DecodeFromBase64String(Pubkey);

                AsymmetricKeyAlgorithmProvider provider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
                CryptographicKey publicKey = provider.ImportPublicKey(keyBuffer, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);

                IBuffer dataBuffer = CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(plainText));
                var encryptedData = CryptographicEngine.Encrypt(publicKey, dataBuffer, null);
                return CryptographicBuffer.EncodeToBase64String(encryptedData);

            }
            catch (Exception e)
            {
                Debug.WriteLine(e.ToString());
                return "Error in Encryption:With RSA ";
            }
        }
    }
}
