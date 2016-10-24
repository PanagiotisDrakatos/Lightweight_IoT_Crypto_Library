using SecureUWPChannel.Interfaces;
using SecureUWPClient.Ciphers.AES;
using SecureUWPClient.Ciphers.RSA;
using SecureUWPClient.Ciphers.Symmetric;
using SecureUWPClient.Configuration;
using SecureUWPClient.Handshake;
using SecureUWPClient.KeyManager;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace SecureUWPClient
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private String receive = null;
        public MainPage()
        {
            this.InitializeComponent();
            //Debug.WriteLine(new testing().pseudorandom());
          //  StartAsync();
            SSLtimeConn();
        }

        private async void StartAsync()
        {
            IOSessionBuilder ses = new IOSessionBuilder();
            await ses.InitializeAsync();
            ses.EstablishDHkeySession();
            Object obj = await ses.ChooseCipher();
            IOCallbackAsync messageExhange = ses.MessageExhange;
            if (obj.GetType() == (typeof(AES_CBC)))
            {
                await messageExhange.SendDHEncryptedMessage("hello server", (AES_CBC)obj);
                receive = await messageExhange.ReceiveDHEncryptedMessage((AES_CBC)obj);
            }
            else if(obj.GetType() == typeof(AES_ECB))
            {
                await messageExhange.SendDHEncryptedMessage("hello server", (AES_ECB)Convert.ChangeType(obj.GetType(), typeof(AES_ECB)));
                receive = await messageExhange.ReceiveDHEncryptedMessage((AES_ECB)Convert.ChangeType(obj.GetType(), typeof(AES_ECB)));
            }
            ses.Close();

        }

        private async void SSLtimeConn()
        {
            IOSessionBuilder ses = new IOSessionBuilder();
            long time= await ses.SSLConnAsyncTime();
        }



    }
}
