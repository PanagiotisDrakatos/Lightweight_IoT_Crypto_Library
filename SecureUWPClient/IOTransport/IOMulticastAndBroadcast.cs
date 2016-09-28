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

namespace SecureUWPChannel.IOTransport
{
    public class IOMulticastAndBroadcast
    {
        private string utf8String;
        private StreamSocket socket;
        public byte[] utf8Bytes;
        private HostParameters SocksParameters;
        //   private String protocol;


        public IOMulticastAndBroadcast(StreamSocket socket, String host, String port)
        {
            SocksParameters = new HostParameters();
            SocksParameters.Host = host;
            SocksParameters.Port = port;
            this.socket = socket;
        }

        public async Task connect()
        {


            try
            {
                HostName hostName;

                hostName = new HostName(SocksParameters.Host);
                socket.Control.NoDelay = false;
                var cts = new CancellationTokenSource();
                cts.CancelAfter(SampleConfiguration.timeout);

                // Connect to the server
                var connectAsync = socket.ConnectAsync(hostName, SocksParameters.Port);
                var connectTask = connectAsync.AsTask(cts.Token);
                await connectTask;
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.ToString());
                await new MessageDialog("Make sure your Server is open and make sure you follow Instructions To connect localhost").ShowAsync();
                Application.Current.Exit();
            }

        }


        public async Task send(String message)
        {

            DataWriter writer;
            // Create the data writer object backed by the in-memory stream. 
            using (writer = new DataWriter(socket.OutputStream))
            {
                try
                {
                    Encoding utf8 = Encoding.UTF8;
                    Encoding unicode = Encoding.Unicode;
                    writer.UnicodeEncoding = Windows.Storage.Streams.UnicodeEncoding.Utf8;
                    writer.WriteString(message);
                    await writer.StoreAsync();
                    await writer.FlushAsync();
                    writer.DetachStream();
                    writer.Dispose();
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
        }


        public async Task<String> read()
        {
            DataReader reader;
            StringBuilder strBuilder;



            using (reader = new DataReader(socket.InputStream))
            {

                try
                {
                    strBuilder = new StringBuilder();
                    reader.InputStreamOptions = Windows.Storage.Streams.InputStreamOptions.Partial;
                 
                    reader.UnicodeEncoding = Windows.Storage.Streams.UnicodeEncoding.Utf8;
                    reader.ByteOrder = Windows.Storage.Streams.ByteOrder.LittleEndian;

                    await reader.LoadAsync(256);
                    while (reader.UnconsumedBufferLength > 0)
                    {
                        strBuilder.Append(reader.ReadString(reader.UnconsumedBufferLength));
                        await reader.LoadAsync(256);
                    }

                    reader.DetachStream();
                    return strBuilder.ToString();
                }
                catch (Exception e)
                {    
                    return (e.ToString());

                }
            }

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
