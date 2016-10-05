using System;
using System.Diagnostics;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace SecureUWPClient.KeyManager
{
   public class DHIntegrityKey:Keys
    {

       private CryptographicKey integrityKey;
       private String SessionKey;

    public DHIntegrityKey() : base(Type.DHIntegrityKey)
    {
          Debug.WriteLine("Cretaed!!!");
    }

        public void GenerateIntegrityKey(String SessionKey)
    {
            this.SessionKey = SessionKey;
            IBuffer keyBuffer = CryptographicBuffer.ConvertStringToBinary(SessionKey, BinaryStringEncoding.Utf8);
            byte[] keyBytes;
            byte[] keyBytes16 = new byte[16];

            CryptographicBuffer.CopyToByteArray(keyBuffer, out keyBytes);
            Array.Copy(keyBytes, Math.Min(keyBytes.Length / 2, 16), keyBytes16, 0, Math.Min(keyBytes.Length, 16));

            IBuffer cipherBuffer = CryptographicBuffer.CreateFromByteArray(keyBytes16);

            SymmetricKeyAlgorithmProvider objKdfProv = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            CryptographicKey key = objKdfProv.CreateSymmetricKey(cipherBuffer);
            this.IntegrityKey = key;
        }
        public CryptographicKey IntegrityKey
        {
            get
            {
                return integrityKey;
            }
            set
            {
                integrityKey = value;
            }
        }
        public override String RetriveSessionKey()
    {
        return this.SessionKey;
    }

   }
}
