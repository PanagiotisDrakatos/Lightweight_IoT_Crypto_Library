using System;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Certificates;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
namespace SecureUWPClient
{
    public class testing
    {
        private int seed = 45;
        public testing()
        {
            
        //   plzz();
        }


        private async void plzz()
        {
            string key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgWyAXzrKa5Y8QwJnkmWPekt6rZ6BDtqJcPenCElB6bCgLvBJShWJO3e+c3FVV3sctBkTiKC0Ij9kcmEJ/ksqgmrGwB82Or4orv/2mHOdf0yugymW4XwsIoMfqi0XuuqScu8jvYz6g9iTFNgm/TZZvj6UZafhpilSHpeZA8M5bpijPtF+tjq3SyQkxUapCGDfuf/EeupxzwqYTLRIGluxE+LqrxXCx1t3QyKpa3013N8HPqTDxaMxIMB/4fg3CHJ2CHixfFKjbNAehtj5CsSv5Eskj75iyqAF5dh4BZt0pv0LpLXpUh7w82LgSoVi2g7NlwxYOX7XEAKIVB6aiv0VGQIDAQAB";
            string cert = "MIID/TCCAuWgAwIBAgIBATANBgkqhkiG9w0BAQUFADBjMRQwEgYDVQQDEwtleGFtcGxlLm9yZzELMAkGA1UEBhMCR1IxDzANBgNVBAgTBkF0aGVuczEPMA0GA1UEBxMGQXRoZW5zMQ0wCwYDVQQKEwRUZXN0MQ0wCwYDVQQLEwRUZXN0MB4XDTE2MDkxODE5NDkzMFoXDTE3MDkxODE5NDkzMFowYzEUMBIGA1UEAxMLZXhhbXBsZS5vcmcxCzAJBgNVBAYTAkdSMQ8wDQYDVQQIEwZBdGhlbnMxDzANBgNVBAcTBkF0aGVuczENMAsGA1UEChMEVGVzdDENMAsGA1UECxMEVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIFsgF86ymuWPEMCZ5Jlj3pLeq2egQ7aiXD3pwhJQemwoC7wSUoViTt3vnNxVVd7HLQZE4igtCI/ZHJhCf5LKoJqxsAfNjq+KK7/9phznX9MroMpluF8LCKDH6otF7rqknLvI72M+oPYkxTYJv02Wb4+lGWn4aYpUh6XmQPDOW6Yoz7RfrY6t0skJMVGqQhg37n/xHrqcc8KmEy0SBpbsRPi6q8Vwsdbd0MiqWt9NdzfBz6kw8WjMSDAf+H4Nwhydgh4sXxSo2zQHobY+QrEr+RLJI++YsqgBeXYeAWbdKb9C6S16VIe8PNi4EqFYtoOzZcMWDl+1xACiFQemor9FRkCAwEAAaOBuzCBuDAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC9DA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwEQYJYIZIAYb4QgEBBAQDAgD3MCwGA1UdEQQlMCOGG2h0dHA6Ly9leGFtcGxlLm9yZy93ZWJpZCNtZYcEfwAAATAdBgNVHQ4EFgQUwOcGIZDvBxPH5FJ2ZKo6YoK1oIswDQYJKoZIhvcNAQEFBQADggEBAARO4d3/JNRmTg33HQ2OigiQ3yh/RCd2u9tF39EmU1tpg/nGMnVql+c+M7TnX51vqGJ2oX5nCY/vM2LgUGCqRcuZLRk2u0SzlaI1QlEPLLnsoCes5rU1tVm8xSUOVYp809F8Eiih0A+NZWbPuT83UgiJVtYOvvEWsnlpErkeP4KblS3z532651pTC/RzKO1saRPx4kBI7QAGogEtjbhvMX8099g0mBHvXcVxrIMTUY4sKntMlYQ4vQ4OxBTEXhKwEW1WJh8orXl3E0EkTFhbjkFE9gbqsS3h4ridMcmahoeIwnwckaU5zxgJ2t3ih35FzZXBmfv3qRgFG81Gdi+NH1U=";
            await RsaEncrypt("d", key, cert);
        }
        public async Task<String> RsaEncrypt(String plainText, string publicKeyString,string cert)
        {
            try
            {

                // The next line fails with ASN1 bad tag value met
                IBuffer keyBuffer = CryptographicBuffer.DecodeFromBase64String(publicKeyString);
                IBuffer certBuffer = CryptographicBuffer.DecodeFromBase64String(cert);
                Certificate ft = new Certificate(certBuffer);
                CryptographicKey keyPair = PersistedKeyProvider.OpenPublicKeyFromCertificate(ft, HashAlgorithmNames.Sha1,CryptographicPadding.RsaPkcs1V15);
                Debug.WriteLine("sadsad  "+keyPair.KeySize);
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

        public String pseudorandom()
        {
             int seed = 45;
             double num = Math.Sin(seed) * (0.5);
            return num.ToString("G15");
        }


    }
}
