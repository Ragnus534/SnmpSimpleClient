using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SnmpSimpleClientProject
{
    public  class SnmpAgent
    {
        void GetV2(string ipAddres,int port,string community,string oid)
        {
            Messenger.Get(VersionCode.V2,
                                new IPEndPoint(IPAddress.Parse(ipAddres), port),
                                new OctetString(community),
                                new List<Variable> { new Variable(new ObjectIdentifier(oid)) },
                                60000);



        }

        void SetV2(string ipAddres, int port, string community, string oid,string newValue)
        {
    
            Messenger.Set(VersionCode.V2,
                           new IPEndPoint(IPAddress.Parse(ipAddres), port),
                           new OctetString(community),
                           new List<Variable> { new Variable(new ObjectIdentifier(oid), new OctetString(newValue)) },
                           60000);
        }
    }
}
