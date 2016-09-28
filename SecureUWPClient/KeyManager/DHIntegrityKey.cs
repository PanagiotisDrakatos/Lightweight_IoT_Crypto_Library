using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.KeyManager
{
   public class DHIntegrityKey:Keys
    {

    private String SessionKey;

    public DHIntegrityKey() : base(Type.DHIntegrityKey)
    {
          Debug.WriteLine("Cretaed!!!");
    }

        public void GenerateIntegrityKey(String SessionKey)
    {
        
    }

    public override String RetriveSessionKey()
    {
        return this.SessionKey;
    }

   }
}
