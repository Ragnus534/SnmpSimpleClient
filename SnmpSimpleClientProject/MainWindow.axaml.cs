using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using TimeoutException = Lextm.SharpSnmpLib.Messaging.TimeoutException;

namespace SnmpSimpleClientProject
{
    public partial class MainWindow : Window
    {
        private Label labelForSet;
        private TextBox txtForSnmpSet;
        bool getOperation;

        bool v3ButtonCheck;
        bool v2ButtonCheck;

        public MainWindow()
        {
            InitializeComponent();

            labelForSet = new Label() { Content = "SET: " };
            txtForSnmpSet = new TextBox();
            txtForSnmpSet.Margin = new Thickness(5);
            txtForSnmpSet.Name = "oidSetTxtBox";
            getOperation = true;
            v3ButtonCheck = true;
        }

        public void GetPropertyChecked(object sender, RoutedEventArgs e)
        {
            snmpActionPanel.Children.Remove(labelForSet);
            snmpActionPanel.Children.Remove(txtForSnmpSet);
            getOperation = true;
        }

        public void SetPropertyChecked(object sender, RoutedEventArgs e)
        {
            snmpActionPanel.Children.Insert(snmpActionPanel.Children.Count - 1, labelForSet);
            snmpActionPanel.Children.Insert(snmpActionPanel.Children.Count - 1, txtForSnmpSet);
            getOperation = false;
        }

        public void Action(object sender, RoutedEventArgs e)
        {
            new Thread(() =>
            {
                var auth = new MD5AuthenticationProvider(new OctetString(authPasswordTxtBox.Text));
                var priv = new DESPrivacyProvider(new OctetString(privPasswordTxtBox.Text), auth);

                try
                {
                    Discovery discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
                    ReportMessage report = discovery.GetResponse(2000, new IPEndPoint(IPAddress.Parse(ipAddressTxtBox.Text), 161));

                    if (getOperation)
                    {
                        GetRequestMessage request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(userNameTxtBox.Text), new List<Variable> { new Variable(new ObjectIdentifier(oidGetTxtBox.Text)) }, priv, Messenger.MaxMessageSize, report);
                        ISnmpMessage reply = request.GetResponse(60000, new IPEndPoint(IPAddress.Parse(ipAddressTxtBox.Text), 161));
                        if (reply.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                        {
                            logTxtBox.Text += Environment.NewLine + "error in response";
                        }
                        else
                        {
                            foreach (Variable oidReply in reply.Pdu().Variables)
                            {
                                logTxtBox.Text += Environment.NewLine + "OID " + oidGetTxtBox.Text + ": " + oidReply.Data.ToString();
                            }

                        }
                    }
                    else
                    {
                        SetRequestMessage request = new SetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(userNameTxtBox.Text), new List<Variable> { new Variable(new ObjectIdentifier(oidGetTxtBox.Text), new OctetString(txtForSnmpSet.Text)) }, priv, Messenger.MaxMessageSize, report);
                        ISnmpMessage reply = request.GetResponse(60000, new IPEndPoint(IPAddress.Parse(ipAddressTxtBox.Text), 161));
                        if (reply.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                        {
                            logTxtBox.Text += Environment.NewLine + "error in response";
                        }
                        else
                        {
                            foreach (Variable oidReply in reply.Pdu().Variables)
                            {
                                logTxtBox.Text += Environment.NewLine + "OID " + oidGetTxtBox.Text + ": " + oidReply.Data.ToString();
                            }

                        }
                    }
                }
                catch (TimeoutException ex)
                {
                    Dispatcher.UIThread.Post(() => { logTxtBox.Text += Environment.NewLine + "Problem with connection"; });
                }

            }).Start();
        }

        public void V3ButtonClicked(object sender, RoutedEventArgs e)
        {
            V2Button.IsChecked = false;
            V3Button.IsChecked = true;
        }

        public void V2ButtonClicked(object sender, RoutedEventArgs e)
        {
            V3Button.IsChecked = false;
            V2Button.IsChecked = true;

        }
    }
}