using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SnmpSimpleClientProject
{
    public class SnmpAgent
    {
        string GetV2(string ipAddres, int port, string community, string oid)
        {
            return Messenger.Get(VersionCode.V2,
                                new IPEndPoint(IPAddress.Parse(ipAddres), port),
                                new OctetString(community),
                                new List<Variable> { new Variable(new ObjectIdentifier(oid)) },
                                60000).ToString();



        }

        string SetV2(string ipAddres, int port, string community, string oid, string newValue)
        {

            return Messenger.Set(VersionCode.V2,
                            new IPEndPoint(IPAddress.Parse(ipAddres), port),
                            new OctetString(community),
                            new List<Variable> { new Variable(new ObjectIdentifier(oid), new OctetString(newValue)) },
                            60000).ToString();
        }

        string GetV3(string ipAddres, int port, string authPassword, string privPassword, string username, string oid)
        {
            string valueToReturn = string.Empty;
            var auth = new MD5AuthenticationProvider(new OctetString(authPassword));
            var priv = new DESPrivacyProvider(new OctetString(privPassword), auth);

            try
            {
                Discovery discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
                ReportMessage report = discovery.GetResponse(2000, new IPEndPoint(IPAddress.Parse(ipAddres), 161));

                GetRequestMessage request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(username), new List<Variable> { new Variable(new ObjectIdentifier(oid)) }, priv, Messenger.MaxMessageSize, report);
                ISnmpMessage reply = request.GetResponse(60000, new IPEndPoint(IPAddress.Parse(ipAddres), port));
                if (reply.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                {
                    valueToReturn =  Environment.NewLine + "error in response";
                }
                else
                {
                    foreach (Variable oidReply in reply.Pdu().Variables)
                    {
                        valueToReturn = Environment.NewLine + "OID " + oid + ": " + oidReply.Data.ToString();
                    }

                }

            }
            catch (Lextm.SharpSnmpLib.Messaging.TimeoutException ex)
            {
                valueToReturn = Environment.NewLine + "Problem with connection";
            }

            return valueToReturn;

        }

        string SetV3(string ipAddres, int port, string authPassword, string privPassword, string username, string oid,string value)
        {
            string valueToReturn = string.Empty;
            var auth = new MD5AuthenticationProvider(new OctetString(authPassword));
            var priv = new DESPrivacyProvider(new OctetString(privPassword), auth);

            Discovery discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
            ReportMessage report = discovery.GetResponse(2000, new IPEndPoint(IPAddress.Parse(ipAddres), 161));
            try
            {
                SetRequestMessage request = new SetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(username), new List<Variable> { new Variable(new ObjectIdentifier(oid), new OctetString(value)) }, priv, Messenger.MaxMessageSize, report);
                ISnmpMessage reply = request.GetResponse(60000, new IPEndPoint(IPAddress.Parse(ipAddres), port));
                if (reply.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                {
                    valueToReturn =  Environment.NewLine + "error in response";
                }
                else
                {
                    foreach (Variable oidReply in reply.Pdu().Variables)
                    {
                        valueToReturn = Environment.NewLine + "OID " + oid + ": " + oidReply.Data.ToString();
                    }

                }
            }
            catch (Lextm.SharpSnmpLib.Messaging.TimeoutException ex)
            {
                valueToReturn = Environment.NewLine + "Problem with connection"; ;
            }

            return valueToReturn;
        }


    }
}
