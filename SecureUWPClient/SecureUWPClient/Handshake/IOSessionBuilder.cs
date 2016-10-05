using SecureUWPChannel.Interfaces;
using SecureUWPChannel.IOTransport;
using SecureUWPChannel.Prooperties;
using SecureUWPClient.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking.Sockets;

namespace SecureUWPClient.Handshake
{
    public class IOSessionBuilder
    {
        private StreamSocket CommunicationSocket;
        private CiphersForUse ciphersforUse;
        private IAsyncSynAck DHsession;

        public IOSessionBuilder()
        {

           
        }
        public async Task InitializeAsync()
        {
            using (CommunicationSocket = new StreamSocket())
            {

                try
                {
                    IOMulticastAndBroadcast Activity = new IOMulticastAndBroadcast(CommunicationSocket,
                        SampleConfiguration.Host,
                        SampleConfiguration.ConnectionPort);
                    await Activity.connect();

                    DHsession = new DHkeyExchange(Activity);
                    EstablishDHkeySession();
                }
                catch (Exception exception)
                {
                    CommunicationSocket.Dispose();
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
        private async void EstablishDHkeySession()
        {
           long elapsed=ExecutionTime.CurrentTimeMillis();
           await DHsession.SendPlainMessage();
           await this.DHsession.ReceiveServerCertificate();
           await this.DHsession.ResendCookieServer();
           await this.DHsession.SendPublicValue();
           await this.DHsession.ReceivePublicValue();
           await this.DHsession.SendCipherSuites();
           ciphersforUse = await this.DHsession.ReceiveCipherSuites();
           Debug.WriteLine("---------------Sum up Time------------------------ " + (ExecutionTime.CurrentTimeMillis() - elapsed));
        }

      

        private String serverMessage;
        public String ServerMessage
        {
            get { return serverMessage; }
            set { serverMessage = value; }
        }

    }
}
