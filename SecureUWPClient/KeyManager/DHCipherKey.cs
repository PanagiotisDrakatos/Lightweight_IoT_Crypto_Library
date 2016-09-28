using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.KeyManager
{
    public class DHCipherKey:Keys
    {

    private String CipherKey;
    private String SessionKey;

    public DHCipherKey() : base(Type.DHCipherKey)
    {
       Debug.WriteLine("Cretaed!!!"); 
    }

    public void GenerateCipherKey(String SessionKey)
    {
    }

    public override String RetriveSessionKey()
    {
        return this.SessionKey;
    }

    public String getCipherKey()
    {
        return CipherKey;
    }


}
}
