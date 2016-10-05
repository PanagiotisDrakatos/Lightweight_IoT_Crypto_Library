using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace SecureUWPClient.Ciphers.AES
{
    public class HMacAlgoProvider
    {


        public static String CreateHMAC(String Data, CryptographicKey hmacKey, String strAlgName)
        {
            MacAlgorithmProvider objMacProv = MacAlgorithmProvider.OpenAlgorithm(strAlgName);
            IBuffer bufMsg = CryptographicBuffer.CreateFromByteArray(System.Text.Encoding.UTF8.GetBytes(Data));
            IBuffer buffHMAC = CryptographicEngine.Sign(hmacKey, bufMsg);

            // Verify that the HMAC length is correct for the selected algorithm
            if (buffHMAC.Length != objMacProv.MacLength)
            {
                throw new Exception("Error computing digest");
            }

            return CryptographicBuffer.EncodeToBase64String(buffHMAC);
        }

        public static bool VerifyHMAC(String Data, CryptographicKey hmacKey, String HmacMsg, String strAlgName)
        {
            String ServerHmacSign = CreateHMAC(Data, hmacKey, strAlgName);
            if (HmacMsg.Equals(ServerHmacSign))
            {
                Debug.WriteLine("Integrity of Symetrickey verified successfully");
                return true;
            }
            else {
                Debug.WriteLine("Integrity of Symetrickey can not be verified");
                Debug.WriteLine(HmacMsg);
                Debug.WriteLine(ServerHmacSign);
                return false;
            }

        }

    }
  }