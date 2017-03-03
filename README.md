
# Lightweight_IoT_Crypto_Library
<p>A cross Platform Encryption Library which Interact with Many Programming Languages Provides a Lightweight Encryption for all Devices. It gives the oportunity in many Companies to Interact with a server wrriten in pure node.js which can  feeds data across  any device or across any pc where supported this Programming Languages(Java,android,UWP,IOS,python)</p>

# Getting Started
<p> <b>Lightweight_IoT_Crypto_Library </b>Encryption aims at providing an easy-to-use Cross Platform API which allows an encrypted communication ( multi platform programming languages)over socket which it can be used from every  company or developers who want a High level security inside a network  between multiple cross platform devices</p>

<p>Some of the important characteristics that make Lightweight_IoT_Crypto_Library
such an attractive option  include the following</p>

| Feature            |                         Description                                        |
| -------------      |                       :-------------:                                      | 
|<h6>Scalability</h6>|<p>Multi platform programming languages system scales easily with no downtime.</p>| 
|<h6>Reliability</h6>|<p>Ensure the reliability of Diffie Hellman Key  based the model  designed to guide policies for information     security within an organization, the well known as CIA(Confidentiality,Integrity,Availability).  </p>  |  
|<h6>Performance</h6>| <p>Performance High throughput for both Server and Client, at the Higher layers of the OSI Reference    Model(Application Layer ) that  provide constant performance. </p>                          |        


#Philosophy
<p>The <b>Lightweight_IoT_Crypto_Library </b> philosophy is to provide small, robust tooling for companies to adopt Bring your own device (BYOD) which is refers to the policy of permitting employees to bring personally owned devices (laptops, tablets, and smart phones) to their workplace, and to use those devices to access privileged company information and application with secure </p>

#Quick Start
<p>The quickest way to get started is to install the Server.All what you need to run the server is described below:</p>
 * About 15 minutes
 * A favorite text editor or IDE  (i use this one<a href="https://c9.io/"> c9 ).</a>
 * Node.js v4.6.1 or later
 
<p>The package  can be installed via git clone only (for now). Also you will need to run the Server Locally in order to play the example given. An easy way to do this if you use <a href="https://c9.io/">c9</a> is to follow <a href ="https://www.youtube.com/watch?v=Bhy0vZYElbE">this</a> tutorial </p>
 
 ```
$git clone https://github.com/PanagiotisDrakatos/Lightweight IoT Crypto Library.git
$cd Lightweight IoT Crypto Library
```
<p>Install dependencies:</p>
 ```
$npm install node-rsa
$npm install node-forge
$npm install big-integer
```
#Usage
 ```
$npm start
```
<p>Open a Web browser, go to http://localhost:1337,Navigate in <a href="https://github.com/PanagiotisDrakatos/Lightweight_IoT_Crypto_Library/blob/master/SecureBackend/PlainConnection.js">PlainConnection.js</a> and dont forget to change this lines of code with your values</p>
```Javascript
var _HOST = '192.168.1.68';//your local server ip 
var _PORT = 1337;//your local server port
```
---
<p>et voilà!You are ready to Start the Server By Running the <a href="https://github.com/PanagiotisDrakatosLightweight_IoT_Crypto_Library/blob/master/SecureBackend/PlainConnection.js">PlainConnection.js</a> script</p>
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
<p>Navigate <a href="https://github.com/PanagiotisDrakatos/Lightweight_IoT_Crypto_Library/blob/master/SecureUWPClient/SecureUWPClient/MainPage.xaml.cs">here</a> for furthermore informations of how to run this library in UWP apps</p>
<h2>Android</h2>
<p>Navigate <a href="https://github.com/PanagiotisDrakatos/Lightweight_IoT_Crypto_Library/blob/master/SecureAndroidClient/app/src/main/java/com/security/crypto/MainActivity.java">here</a> for furthermore informations of how to run this library in Android apps</p>


#Contribute
 1. Fork it: git clone https://github.com/PanagiotisDrakatos/Lightweight_IoT_Crypto_Library.git
 2. Create your feature branch: git checkout -b my-new-feature
 3. Commit your changes: git commit -am 'Add some feature'
 4. Push to the branch: git push origin my-new-feature
 5. Submit a pull request :D
 
### License
<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/80x15.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">Creative Commons Attribution-ShareAlike 4.0 International License</a>.
