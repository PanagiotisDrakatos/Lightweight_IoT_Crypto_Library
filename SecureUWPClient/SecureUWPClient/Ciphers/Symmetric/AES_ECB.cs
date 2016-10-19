using SecureUWPClient.Ciphers.Symmetric;
using SecureUWPClient.Handshake;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace SecureUWPClient.Ciphers.Symmetric
{
   public class AES_ECB : Cryptography
    {
        private String encrypted;
        private String decrypted;
        private SupportedChipher cipher;
        public AES_ECB(SupportedChipher cipher)
        {
            this.cipher = cipher;
            this.encrypted = null;
            this.decrypted = null;
        }
        public async Task<String> AeS_Encrypt(string plainText, string EncryptionKey)
        {

            SymmetricKeyAlgorithmProvider SAP = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesEcbPkcs7);
            HashAlgorithmProvider HAP = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
            CryptographicHash Hash_AES = HAP.CreateHash();

            try
            {
                Hash_AES.Append(CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(EncryptionKey)));
                byte[] KeyBytes;
                CryptographicBuffer.CopyToByteArray(Hash_AES.GetValueAndReset(), out KeyBytes);

                CryptographicKey key = SAP.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyBytes));
                IBuffer Buffer = CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(plainText));
                encrypted = CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(key, Buffer, null));

                return encrypted;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.ToString());
                return "Error in Encryption:With Aes ";
            }
        }

        public async Task<String> AeS_Decrypt(String EncryptedText, String DecryptionKey)
        {
            SymmetricKeyAlgorithmProvider SAP = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesEcbPkcs7);
            HashAlgorithmProvider HAP = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
            CryptographicHash Hash_AES = HAP.CreateHash();

            try
            {
                Hash_AES.Append(CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(DecryptionKey)));
                byte[] KeyBytes;
                CryptographicBuffer.CopyToByteArray(Hash_AES.GetValueAndReset(), out KeyBytes);

                CryptographicKey key = SAP.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyBytes));

                IBuffer Buffer = CryptographicBuffer.DecodeFromBase64String(EncryptedText);
                byte[] Decrypted;

                CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(key, Buffer,null), out Decrypted);
                decrypted = System.Text.Encoding.UTF8.GetString(Decrypted, 0, Decrypted.Length);
                return decrypted;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.ToString());
                return "Error in Decryption:With Aes ";
            }

        }

    }
}
