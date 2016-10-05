using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace SecureUWPClient.KeyManager
{
    public class DHCipherKey:Keys
    {

    private String cipherKey;
    private String SessionKey;

    public DHCipherKey() : base(Type.DHCipherKey)
    {
       Debug.WriteLine("Cretaed!!!"); 
    }

    public void GenerateCipherKey(String SessionKey)
    {
            this.SessionKey= SessionKey;
            IBuffer keyBuffer = CryptographicBuffer.ConvertStringToBinary(SessionKey, BinaryStringEncoding.Utf8);
            byte[] keyBytes;
            byte[] keyBytes16 = new byte[16];

            CryptographicBuffer.CopyToByteArray(keyBuffer, out keyBytes);
            Array.Copy(keyBytes, 0, keyBytes16, 0, Math.Min(keyBytes.Length / 2, 16));

            IBuffer cipherBuffer = CryptographicBuffer.CreateFromByteArray(keyBytes16);
            CipherKey = CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8,cipherBuffer);
        }

    public override String RetriveSessionKey()
    {
        return this.SessionKey;
    }

        public string CipherKey
        {
            get
            {
                return cipherKey;
            }
            set
            {
                cipherKey = value;
            }
        }


    }
}
