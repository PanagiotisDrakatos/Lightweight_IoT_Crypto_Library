
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
        public async Task<String> RsaEncrypt(CryptographicKey publicKey,String plainText)
        {
            try
            {
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
