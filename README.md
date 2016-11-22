<h2>Under Construction</h2>

# Light_IoT_CryptoDevice
<p>A cross Platform Encryption Library which Interact with Many Programming Languages Provides a Lightweight Encryption for all Devices. It gives the oportunity in many Companies to Interact with a server wrriten in pure node.js which can  feeds data across  any device or across any pc where supported this Programming Languages(Java,android,UWP,IOS,python)</p>

# Light_IoT_CryptoDevice
<p> <b>Light_IoT_CryptoDevice </b>Encryption aims at providing an easy-to-use Cross Platform API which allows an encrypted communication ( multi platform programming languages)over socket which it can be used from every  company or developers who want a High level security inside a network  between multiple cross platform devices</p>

<p>Some of the important characteristics that make Light_IoT_CryptoDevice
such an attractive option  include the following</p>

| Feature            |                         Description                                        |
| -------------      |                       :-------------:                                      | 
|<h6>Scalability</h6>|<p>Multi platform programming languages system scales easily with no downtime.</p>| 
|<h6>Reliability</h6>|<p>Ensure the reliability of Diffie Hellman Key  based the model  designed to guide policies for information     security within an organization, the well known as CIA(Confidentiality,Integrity,Availability).  </p>  |  
|<h6>Performance</h6>| <p>Performance High throughput for both Server and Client, at the Higher layers of the OSI Reference    Model(Application Layer ) that  provide constant performance. </p>                          |        


#Philosophy
<p>The<b>Light_IoT_CryptoDevice </b> philosophy is to provide small, robust tooling for companies to adopt Bring your own device (BYOD) which is refers to the policy of permitting employees to bring personally owned devices (laptops, tablets, and smart phones) to their workplace, and to use those devices to access privileged company information and application with secure </p>

<h2>Python Manual</h2>
```Python
from Handshake.SessionHandler import HandleSession


# sessi = HandleSession("SSLSocket")
sessi = HandleSession("Plaintext")
try:
    sessi.__StartExhangeKey__()

    sessi.__SendSecurMessage__("Message")
    print(sessi.__ReceiveSecurMessage__())

    sessi.__SendSecurMessage__("Message1")
    print(sessi.__ReceiveSecurMessage__())
except Exception as inst:
    print type(inst)
finally:
    print("closing socket")
    sessi.__Close__()

```
---


<h2>Java Manual</h2>
```java
    import com.security.crypto.Configuration.Properties;
    import com.security.crypto.Handshake.SessionHandler;

/**
 * Hello world!
 */
public class App {
   

    public static void main(String[] args) throws Exception {
        String Receive = null;

        SessionHandler session = new SessionHandler(Properties.PlainTextConnection);
        session.StartDHKeyExchange();

        session.SendSecureMessage("hello Server 1");
        Receive = session.ReceiveSecureMessage();
        System.out.println(Receive);

        session.SendSecureMessage("hello Server 2");
        Receive = session.ReceiveSecureMessage();
        System.out.println(Receive);

        session.ConnectionClose();
    }


}
```
---

<h2>Universal Windows Platform (UWP)</h2>
<p>Navigate <a href="https://github.com/PanagiotisDrakatos/Light_IoT_CryptoDevice/blob/master/SecureUWPClient/SecureUWPClient/MainPage.xaml.cs">here</a> for furthermore informations of how to run this library in UWP apps</p>
<h2>Android</h2>
<p>Navigate <a href="https://github.com/PanagiotisDrakatos/Light_IoT_CryptoDevice/blob/master/SecureAndroidClient/app/src/main/java/com/security/crypto/MainActivity.java">here</a> for furthermore informations of how to run this library in Android apps</p>
