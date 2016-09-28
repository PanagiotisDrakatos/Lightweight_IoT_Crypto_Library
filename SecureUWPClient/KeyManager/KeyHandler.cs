using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        private String Output;
        private Windows.Storage.StorageFile sampleFile;
        public KeyHandler()
        {
            Intialize();
        }

        public override string Server_Certificate
        {
            get
            {
                return Output + _clientFolder+_server_Certificate;
                throw new NotImplementedException();
            }
        }

        public override string Server_PUBLIC_KEY
        {
            get
            {
                return Output + _clientFolder+_server_PUBLIC_KEY;
                throw new NotImplementedException();
            }
        }

        public override string ClientFolder
        {
            get
            {
                return Output + _clientFolder;
                throw new NotImplementedException();
            }
        }

        public override string loadRemoteCipherKey()
        {
            throw new NotImplementedException();
        }

        public override void ProduceCipherKey(string SessionResult)
        {
            throw new NotImplementedException();
        }

        public override void ProduceIntegrityKey(string SessionResult)
        {
            throw new NotImplementedException();
        }

        public override async void SaveCertificate(string CertPemFormat)
        {
            IBuffer certBuffer = CryptographicBuffer.DecodeFromBase64String(CertPemFormat);
            await Windows.Storage.FileIO.WriteTextAsync(sampleFile, CertPemFormat);
            Certificate ft = new Certificate(certBuffer);
            throw new NotImplementedException();
        }

        public override async void SaveServerPublicKey(Certificate cert)
        {
            CryptographicKey keyPair = PersistedKeyProvider.OpenPublicKeyFromCertificate(cert, HashAlgorithmNames.Sha1, CryptographicPadding.RsaPkcs1V15);
            IBuffer keybuffer =keyPair.ExportPublicKey();
            String PublicKey=CryptographicBuffer.EncodeToBase64String(keybuffer);
            await Windows.Storage.FileIO.WriteTextAsync(sampleFile, PublicKey);
            throw new NotImplementedException();
        }

        public override async Task<Certificate> LoadCertificate()
        {
            string CertPemFormat = await Windows.Storage.FileIO.ReadTextAsync(sampleFile);
            IBuffer certBuffer = CryptographicBuffer.DecodeFromBase64String(CertPemFormat);
            Certificate cert = new Certificate(certBuffer);
            return cert;
            throw new NotImplementedException();
        }

        public override async Task<CryptographicKey> LoadPublicKey()
        {
            string Pubkey = await Windows.Storage.FileIO.ReadTextAsync(sampleFile);
            IBuffer keyBuffer = CryptographicBuffer.DecodeFromBase64String(Pubkey);

            AsymmetricKeyAlgorithmProvider provider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
            CryptographicKey publicKey = provider.ImportPublicKey(keyBuffer, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
            return publicKey;
        }
        private async void Intialize()
        {
            bool x = await isFilePresent(ClientFolder);
            if (!x)
                Debug.WriteLine("File eady Created!!!!");

            Windows.ApplicationModel.Package package = Windows.ApplicationModel.Package.Current;
            Windows.Storage.StorageFolder storageFolder =Windows.Storage.ApplicationData.Current.LocalFolder;
            sampleFile = await storageFolder.GetFileAsync("sample.txt");
           // Output = String.Format("Installed Location: {0}", installedLocation.Path);
           
        }

        public async Task<bool> isFilePresent(string fileName)
        {
            var item = await ApplicationData.Current.LocalFolder.TryGetItemAsync(fileName);
            return item != null;
        }
    }
}
