using SecureUWPClient.Handshake;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
            return "";
            
        }

        public async Task<String> AeS_Decrypt(String EncryptedText, String DecryptionKey)
        {
            return "";
        }
    
    }
}
