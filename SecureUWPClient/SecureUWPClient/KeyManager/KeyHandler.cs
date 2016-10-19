using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Certificates;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;

namespace SecureUWPClient.KeyManager
{
    public class KeyHandler : KeyManagerImp
    {
        private  String Output;
        private  DHCipherKey CipherKey;
        private  DHIntegrityKey IntegrityKey;

        private  StorageFolder newFolder;
        private  StorageFile pubFile;
        private  StorageFile certFile;
        private Task t;
        public KeyHandler()
        {
            Intialize();
            this.CipherKey = new DHCipherKey();
            this.IntegrityKey = new DHIntegrityKey();
        }

        public override string Server_Certificate
        {
            get
            {
                return _server_Certificate;
                throw new NotImplementedException();
            }
        }

        public override string Server_PUBLIC_KEY
        {
            get
            {
                return _server_PUBLIC_KEY;
               // throw new NotImplementedException("sadass");
            }
        }

        public override string ClientFolder
        {
            get
            {
                return _clientFolder;
                throw new NotImplementedException("saas");
            }
        }

     

        public override void ProduceCipherKey(string SessionResult)
        {
            CipherKey.GenerateCipherKey(SessionResult);
            return;
        }

        public override void ProduceIntegrityKey(string SessionResult)
        {
            IntegrityKey.GenerateIntegrityKey(SessionResult);
            return;
        }

        public override async  Task<int> SaveCertificate(string CertPemFormat)
        {
            t = Task.Run(async () => {
            StorageFile certFile = await newFolder.GetFileAsync(Server_Certificate);
            var buffer = Windows.Security.Cryptography.CryptographicBuffer.ConvertStringToBinary(CertPemFormat, 
                Windows.Security.Cryptography.BinaryStringEncoding.Utf8);
            await Windows.Storage.FileIO.WriteBufferAsync(certFile, buffer);
            });
            t.Wait();
            return 0; ;
        }

        public override async void SaveServerPublicKey(Certificate cert)
        {
            t = Task.Run(async () => {
            CryptographicKey keyPair = PersistedKeyProvider.OpenPublicKeyFromCertificate(cert, HashAlgorithmNames.Sha1, CryptographicPadding.RsaPkcs1V15);
            IBuffer keybuffer =keyPair.ExportPublicKey();
            String PublicKey=CryptographicBuffer.EncodeToBase64String(keybuffer);
            StorageFile pubFile = await newFolder.GetFileAsync(Server_PUBLIC_KEY);
            var buffer = Windows.Security.Cryptography.CryptographicBuffer.ConvertStringToBinary(PublicKey,
             Windows.Security.Cryptography.BinaryStringEncoding.Utf8);
            await Windows.Storage.FileIO.WriteBufferAsync(pubFile, buffer);
            });
            t.Wait();
            return;
        }

        public override async Task<Certificate> LoadCertificate()
        {
            Certificate cert = null;
            string CertPemFormat = null;
            try
            {
                    StorageFolder loclfold = await ApplicationData.Current.LocalFolder.GetFolderAsync(ClientFolder);
                    var buffer = await Windows.Storage.FileIO.ReadBufferAsync(await loclfold.GetFileAsync(Server_Certificate));
                    using (var dataReader = Windows.Storage.Streams.DataReader.FromBuffer(buffer))
                    {
                        CertPemFormat = dataReader.ReadString(buffer.Length);
                    }
                    Debug.WriteLine(CertPemFormat);
                    IBuffer certBuffer = CryptographicBuffer.DecodeFromBase64String(CertPemFormat);
                    cert = new Certificate(certBuffer);
                    return cert;
                
            }
            catch (FileNotFoundException e)
            {
                Debug.WriteLine("Folder Not Exists!!!" + e.Data);
            }
            return cert;
        }

        public override async Task<String> LoadPublicKey()
        {
            string Pubkey = null;
            try
            {
             
                StorageFolder loclfold = await ApplicationData.Current.LocalFolder.GetFolderAsync(ClientFolder);
                var buffer = await Windows.Storage.FileIO.ReadBufferAsync(await loclfold.GetFileAsync(Server_PUBLIC_KEY));
                using (var dataReader = Windows.Storage.Streams.DataReader.FromBuffer(buffer))
                {
                    Pubkey = dataReader.ReadString(buffer.Length);
                }

                return Pubkey;
            }
            catch (FileNotFoundException e)
            {
                Debug.WriteLine("Folder Not Exists!!!" + e.Data);
                return Pubkey;
            }
        }

        public override async Task<String> LoadIntegrityKey()
        {
            return this.IntegrityKey.IntegrityKey;
        }

        public override async Task<String> LoadCipherKey()
        {
            return this.CipherKey.CipherKey;
        }
        private async void Intialize()
        {
            t = Task.Run(() => isFilePresent(ClientFolder));
            t.Wait();
            return;
        }

        public async Task<bool> isFilePresent(string fileName)
        {
            try {
                StorageFolder appInstalledFolder = ApplicationData.Current.LocalFolder;


                newFolder = await appInstalledFolder.CreateFolderAsync(ClientFolder, CreationCollisionOption.ReplaceExisting);
          
                await newFolder.CreateFileAsync(Server_PUBLIC_KEY, CreationCollisionOption.ReplaceExisting);
                await newFolder.CreateFileAsync(Server_Certificate, CreationCollisionOption.ReplaceExisting);

                // certFile = await newFolder.GetFileAsync(Server_Certificate);
               //  pubFile = await newFolder.GetFileAsync(Server_PUBLIC_KEY);
                Debug.WriteLine(newFolder.Path);
                return true;
            }
            catch(Exception e)
            {
                Debug.WriteLine("Folder Already Exists!!!" + e.Data);
                return false;
            }
        }

    }
}
