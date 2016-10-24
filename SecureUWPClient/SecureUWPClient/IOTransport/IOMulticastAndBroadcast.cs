using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;
using Newtonsoft.Json;
using SecureUWPChannel.Serialization;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using System.Threading;
using SecureUWPChannel.Prooperties;
using Windows.Security.Cryptography;
using Windows.ApplicationModel.Background;
using System.IO;
using SecureUWPClient.Configuration;
using Windows.Security.Cryptography.Certificates;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace SecureUWPChannel.IOTransport
{
    public class IOMulticastAndBroadcast
    {
        private string utf8String;
        private Windows.Networking.Sockets.StreamSocket socket;
        public byte[] utf8Bytes;
        private HostParameters SocksParameters;
        private DataReader _socketReader;
        private StreamWriter _socketWriter;


        public IOMulticastAndBroadcast(String host, String port)
        {
            SocksParameters = new HostParameters();
            SocksParameters.Host = host;
            SocksParameters.Port = port;
            this.socket = new Windows.Networking.Sockets.StreamSocket();
        }
       
        public async Task<long> UpgradeToSSL()
        {
            long elapsed = ExecutionTime.CurrentTimeMillis();
            Windows.Security.Cryptography.Certificates.Certificate certificate = await GetClientCert();
            socket.Control.ClientCertificate = certificate;
      
                if (socket.Information.ServerCertificateErrorSeverity == SocketSslErrorSeverity.Ignorable && socket.Information.ServerCertificateErrors.Count > 0)
                {
                    socket.Control.IgnorableServerCertificateErrors.Clear();
                    foreach (ChainValidationResult ignorableError in socket.Information.ServerCertificateErrors)
                    {
                        socket.Control.IgnorableServerCertificateErrors.Add(ignorableError);
                    }
                    await socket.ConnectAsync(new Windows.Networking.HostName(SocksParameters.Host), SocksParameters.Port, SocketProtectionLevel.Tls12);
                    Debug.WriteLine(socket.Information.RemoteHostName);
                }
            
            long executetTime= ExecutionTime.CurrentTimeMillis() - elapsed;
            return executetTime;
        }
        
        public async Task<Certificate> GetClientCert()
        {
            Certificate crt = null;
            try {
                //new Uri("ms-appx://SecureUWPClient/Certificate/clients.crt")
                Windows.Storage.StorageFile sampleFile = await StorageFile.GetFileFromApplicationUriAsync(new Uri("ms-appx:///Certificates/client.pfx"));
                IBuffer certBuffer = await Windows.Storage.FileIO.ReadBufferAsync(sampleFile);
                String encodedCertificate = CryptographicBuffer.EncodeToBase64String(certBuffer);
                IBuffer Encodebuff = CryptographicBuffer.ConvertStringToBinary(encodedCertificate, BinaryStringEncoding.Utf8);
              //  await CertificateEnrollmentManager.InstallCertificateAsync(encodedCertificate, InstallOptions.None);
                //   await CertificateEnrollmentManager.UserCertificateEnrollmentManager.InstallCertificateAsync(encodedCertificate, InstallOptions.None);
              //  await CertificateEnrollmentManager.ImportPfxDataAsync(encodedCertificate, "password",
              //    ExportOption.NotExportable,KeyProtectionLevel.NoConsent,InstallOptions.None, "UWPClient");
                await CertificateEnrollmentManager.UserCertificateEnrollmentManager.ImportPfxDataAsync(encodedCertificate, "password",
                ExportOption.NotExportable, KeyProtectionLevel.ConsentWithPassword, InstallOptions.None, "UWPClient");
                CertificateQuery certQuery = new CertificateQuery();
                certQuery.FriendlyName = "UWPClient";
                IReadOnlyList<Certificate> certificates = await CertificateStores.FindAllAsync(certQuery);
                if (certificates.Count == 1)
                {
                  
                    crt = certificates[0];
                }
                // CertificateStore.
                //   Certificate crt = new Certificate(Encodebuff);
                return crt;
            }catch(Exception e)
            {
                Debug.WriteLine(e.ToString());
            }
            return null;
        }
        public async Task connect()
        {


            try
            {
                Windows.Networking.HostName serverHost = new Windows.Networking.HostName(SocksParameters.Host);
                socket.Control.NoDelay = false;
                _socketWriter = new StreamWriter(socket.OutputStream.AsStreamForWrite());
                _socketReader = new DataReader(socket.InputStream);
                await socket.ConnectAsync(serverHost, SocksParameters.Port);
                // var cts = new CancellationTokenSource();
                //  cts.CancelAfter(SampleConfiguration.timeout);
                // Connect to the server
                // var connectAsync = socket.ConnectAsync(serverHost, SocksParameters.Port);
                //  var connectTask = connectAsync.AsTask(cts.Token);
                //  await connectTask;
                //Debug.WriteLine(e.ToString());
               // await new MessageDialog("Make sure your Server is open and make sure you follow Instructions To connect localhost").ShowAsync();
               // Application.Current.Exit();
            }
            catch (Exception exception)
            {
                this.socket.Dispose();
                await new MessageDialog("Make sure your Server is open and make sure you follow Instructions To connect localhost").ShowAsync();
                switch (SocketError.GetStatus(exception.HResult))
                {
                    case SocketErrorStatus.HostNotFound:

                        throw;
                    default:

                        throw;
                }
             
            }

        }

       

     
        public async Task send(string request)
        {
            try
            {
                await _socketWriter.WriteLineAsync(request);
                await _socketWriter.FlushAsync();
            }
            catch (Exception exception)
            {
                switch (SocketError.GetStatus(exception.HResult))
                {
                    case SocketErrorStatus.HostNotFound:
                        throw;
                    default:
                        throw;
                }
            }
        }

         public async Task<String> read()
         {
           
             StringBuilder strBuilder;

            _socketReader.InputStreamOptions = Windows.Storage.Streams.InputStreamOptions.Partial;
            _socketReader.UnicodeEncoding = Windows.Storage.Streams.UnicodeEncoding.Utf8;
            _socketReader.ByteOrder = Windows.Storage.Streams.ByteOrder.LittleEndian;

            strBuilder = new StringBuilder();

            var loadsize = await _socketReader.LoadAsync(256);

            while (loadsize >= 256)
            {
                loadsize = await _socketReader.LoadAsync(256);
            }
            if (_socketReader.UnconsumedBufferLength > 0)
            {
                strBuilder.Append(_socketReader.ReadString(_socketReader.UnconsumedBufferLength));
            }
            return strBuilder.ToString();
        }




        public async void close()
        {
            await socket.CancelIOAsync();
        }

        private class HostParameters
        {
            private String host;
            private String port;

            public string Host
            {
                get
                {
                    return host;
                }
                set
                {
                    host = value;
                }
            }


            public string Port
            {
                get
                {
                    return port;
                }
                set
                {
                    port = value;
                }
            }

        }

    }
}
