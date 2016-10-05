using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureUWPClient.KeyManager
{
    public abstract class Keys
    {

        private Type type;

       public enum Type
        {

            DHCipherKey, DHIntegrityKey
        }


        public Keys(Type type)
        {
            this.type = type;
        }

        public Boolean isType(Type type)
        {
            return (this.type == type);
        }


        public abstract String RetriveSessionKey();
    }
}
