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

        bool v3;

        public MainWindow()
        {

            InitializeComponent();

            labelForSet = new Label() { Content = "SET: " };
            txtForSnmpSet = new TextBox();
            txtForSnmpSet.Margin = new Thickness(5);
            txtForSnmpSet.Name = "oidSetTxtBox";
            getOperation = true;

            userNameLab.IsVisible = true;
            userNameLab.IsVisible = true;
            userNameTxtBox.IsVisible = true;
            privPassLab.IsVisible = true;
            privPasswordTxtBox.IsVisible = true;
            authPassLab.IsVisible = true;
            authPasswordTxtBox.IsVisible = true;
            communityLab.IsVisible = false;
            communityTxtBox.IsVisible = false;
            v3 = true;
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
                if (v3)
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
                                Dispatcher.UIThread.Post(() =>
                                {
                                    logTxtBox.Text += Environment.NewLine + "error in response";
                                });
                            }
                            else
                            {
                                foreach (Variable oidReply in reply.Pdu().Variables)
                                {
                                    Dispatcher.UIThread.Post(() =>
                                    {
                                        logTxtBox.Text += Environment.NewLine + "OID " + oidGetTxtBox.Text + ": " + oidReply.Data.ToString();
                                    });
                                }

                            }
                        }
                        else
                        {
                            SetRequestMessage request = new SetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(userNameTxtBox.Text), new List<Variable> { new Variable(new ObjectIdentifier(oidGetTxtBox.Text), new OctetString(txtForSnmpSet.Text)) }, priv, Messenger.MaxMessageSize, report);
                            ISnmpMessage reply = request.GetResponse(60000, new IPEndPoint(IPAddress.Parse(ipAddressTxtBox.Text), 161));
                            if (reply.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                            {
                                Dispatcher.UIThread.Post(() =>
                                {
                                    logTxtBox.Text += Environment.NewLine + "error in response";
                                });
                            }
                            else
                            {
                                foreach (Variable oidReply in reply.Pdu().Variables)
                                {
                                    Dispatcher.UIThread.Post(() => { logTxtBox.Text += Environment.NewLine + "OID " + oidGetTxtBox.Text + ": " + oidReply.Data.ToString(); });
                                }

                            }
                        }
                    }
                    catch (TimeoutException ex)
                    {
                        Dispatcher.UIThread.Post(() => { logTxtBox.Text += Environment.NewLine + "Problem with connection"; });
                    }
                }
                else
                {
                    try
                    {


                        if (getOperation)
                        {
                            Dispatcher.UIThread.Post(() =>
                            {
                                var results = Messenger.Get(VersionCode.V2,
                                    new IPEndPoint(IPAddress.Parse(ipAddressTxtBox.Text), 161),
                                    new OctetString(communityTxtBox.Text),
                                    new List<Variable> { new Variable(new ObjectIdentifier(oidGetTxtBox.Text)) },
                                    60000);

                                foreach(var result in results)
                                {
                                    logTxtBox.Text += Environment.NewLine + "OID " + result.Id + ": " + result.Data.ToString();
                                }

                                
                            });
                        }
                        else
                        {
                            Dispatcher.UIThread.Post(() =>
                            {
                                IList<Variable> results2 =  Messenger.Set(VersionCode.V2,
                                new IPEndPoint(IPAddress.Parse(ipAddressTxtBox.Text), 161),
                                new OctetString(communityTxtBox.Text),
                                new List<Variable> { new Variable(new ObjectIdentifier(oidGetTxtBox.Text), new OctetString(txtForSnmpSet.Text)) },
                                60000);

                                foreach (Variable result2 in results2)
                                {
                                    logTxtBox.Text += Environment.NewLine + "OID " + result2.Id + ": " + result2.Data.ToString();
                                }
                            });
                        }
                    }
                    catch (TimeoutException ex)
                    {
                        Dispatcher.UIThread.Post(() => { logTxtBox.Text += Environment.NewLine + "Problem with connection"; });
                    }
                }

            }).Start();
        }

        public void V3ButtonClicked(object sender, RoutedEventArgs e)
        {
            V3ButtonClicked(sender, e, V3Button);
        }

        public void V3ButtonClicked(object sender, RoutedEventArgs e, Avalonia.Controls.Primitives.ToggleButton v3Button)
        {
            V2Button.IsChecked = false;
            V3Button.IsChecked = true;
            v3 = (bool)V3Button.IsChecked;

            //get ip control 
            userNameLab.IsVisible = true;
            userNameLab.IsVisible = true;
            userNameTxtBox.IsVisible = true;
            privPassLab.IsVisible = true;
            privPasswordTxtBox.IsVisible = true;
            authPassLab.IsVisible = true;
            authPasswordTxtBox.IsVisible = true;
            communityLab.IsVisible = false;
            communityTxtBox.IsVisible = false;

        }

        public void V2ButtonClicked(object sender, RoutedEventArgs e)
        {
            V3Button.IsChecked = false;
            V2Button.IsChecked = true;
            v3 = (bool)V2Button.IsChecked;

            userNameLab.IsVisible = false;
            userNameLab.IsVisible = false;
            userNameTxtBox.IsVisible = false;
            authPassLab.IsVisible = false;
            authPasswordTxtBox.IsVisible = false;
            privPassLab.IsVisible = false;
            privPasswordTxtBox.IsVisible = false;
            communityLab.IsVisible = true;
            communityTxtBox.IsVisible = true;
        }
    }
}