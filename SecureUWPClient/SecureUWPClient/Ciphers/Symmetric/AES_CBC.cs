using SecureUWPClient.Ciphers.Symmetric;
using SecureUWPClient.Handshake;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace SecureUWPClient.Ciphers.AES
{
    public class AES_CBC : Cryptography
    {
        private String encrypted;
        private String decrypted;
        private SupportedChipher cipher;
        private static byte[] ivBytes = new byte[]{0x15, 0x14, 0x13, 0x12, 0x11,
            0x10, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
        public AES_CBC(SupportedChipher cipher) {
            this.cipher = cipher;
            this.encrypted = null;
            this.decrypted = null;
        }
        public async Task<String> AeS_Encrypt(string plainText, string EncryptionKey)
        {

            SymmetricKeyAlgorithmProvider SAP = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            HashAlgorithmProvider HAP = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
            CryptographicHash Hash_AES = HAP.CreateHash();

            try
            {
                //byte[] KeyBytes = System.Text.Encoding.UTF8.GetBytes(password);
              //  byte[] KeyBytes16 = new byte[16];
                Hash_AES.Append(CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(EncryptionKey)));
                byte[] KeyBytes;
                CryptographicBuffer.CopyToByteArray(Hash_AES.GetValueAndReset(), out KeyBytes);
   
                CryptographicKey key = SAP.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyBytes));
                IBuffer Buffer = CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(plainText));
                IBuffer ivparams = CryptographicBuffer.CreateFromByteArray(ivBytes);
                encrypted = CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Encrypt(key, Buffer, ivparams));

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
            SymmetricKeyAlgorithmProvider SAP = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            HashAlgorithmProvider HAP = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);
            CryptographicHash Hash_AES = HAP.CreateHash();

            try
            {
                //byte[] KeyBytes = System.Text.Encoding.UTF8.GetBytes(password);
                Hash_AES.Append(CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(DecryptionKey)));
                byte[] KeyBytes;
                CryptographicBuffer.CopyToByteArray(Hash_AES.GetValueAndReset(), out KeyBytes);
              
                CryptographicKey key = SAP.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(KeyBytes));


                IBuffer Buffer = CryptographicBuffer.DecodeFromBase64String(EncryptedText);
                byte[] Decrypted;

                IBuffer ivparams = CryptographicBuffer.CreateFromByteArray(ivBytes);
                CryptographicBuffer.CopyToByteArray(CryptographicEngine.Decrypt(key, Buffer, ivparams), out Decrypted);
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
