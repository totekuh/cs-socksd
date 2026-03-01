using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SocksDSharp
{
    enum SocksState { Connected, NeedAuth, Authed }

    enum AuthMethod : byte
    {
        NoAuth   = 0x00,
        Username = 0x02,
        Invalid  = 0xFF
    }

    enum SocksError : byte
    {
        Success                 = 0x00,
        GeneralFailure          = 0x01,
        NotAllowed              = 0x02,
        NetworkUnreachable      = 0x03,
        HostUnreachable         = 0x04,
        ConnectionRefused       = 0x05,
        TtlExpired              = 0x06,
        CommandNotSupported     = 0x07,
        AddressTypeNotSupported = 0x08
    }

    static class Log
    {
        public static bool Quiet;

        public static void Info(string msg)
        {
            if (!Quiet) Console.Error.WriteLine(msg);
        }

        public static void Info(string fmt, params object[] args)
        {
            if (!Quiet) Console.Error.WriteLine(fmt, args);
        }
    }

    struct ConnectResult
    {
        public TcpClient Remote;
        public SocksError Error;
        public string Target;
    }

    class SocksServer
    {
        private readonly string _listenIp;
        private readonly int _port;
        private readonly string _authUser;
        private readonly string _authPass;
        private readonly bool _bindMode;
        private readonly bool _authOnce;
        private readonly HashSet<string> _authedIps;
        private readonly object _authLock = new object();
        private IPEndPoint _bindEndPoint;

        public SocksServer(string listenIp, int port, string user, string pass,
                           bool bindMode, bool authOnce)
        {
            _listenIp = listenIp;
            _port = port;
            _authUser = user;
            _authPass = pass;
            _bindMode = bindMode;
            _authOnce = authOnce;
            if (authOnce) _authedIps = new HashSet<string>();
        }

        public async Task RunAsync(CancellationToken ct)
        {
            var listener = new TcpListener(IPAddress.Parse(_listenIp), _port);
            listener.Server.SetSocketOption(
                SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Start();

            Log.Info("Listening on {0}:{1}", _listenIp, _port);

            if (_bindMode)
                _bindEndPoint = new IPEndPoint(IPAddress.Parse(_listenIp), 0);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync()
                        .ConfigureAwait(false);
                    HandleClientAsync(client, ct);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException)
                {
                    continue;
                }
            }
        }

        private async void HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            try
            {
                using (client)
                {
                    client.NoDelay = true;
                    NetworkStream stream = client.GetStream();
                    byte[] buf = new byte[1024];
                    string clientIp = ((IPEndPoint)client.Client.RemoteEndPoint)
                        .Address.ToString();

                    SocksState state = SocksState.Connected;

                    while (true)
                    {
                        int n = await stream.ReadAsync(buf, 0, buf.Length, ct)
                            .ConfigureAwait(false);
                        if (n <= 0) break;

                        switch (state)
                        {
                            case SocksState.Connected:
                                AuthMethod am = CheckAuthMethod(buf, n, clientIp);
                                if (am == AuthMethod.NoAuth)
                                    state = SocksState.Authed;
                                else if (am == AuthMethod.Username)
                                    state = SocksState.NeedAuth;

                                await SendAuthResponse(stream, 0x05, (byte)am)
                                    .ConfigureAwait(false);
                                if (am == AuthMethod.Invalid) return;
                                break;

                            case SocksState.NeedAuth:
                                bool ok = CheckCredentials(buf, n);
                                await SendAuthResponse(stream, 0x01,
                                    (byte)(ok ? 0x00 : 0x01)).ConfigureAwait(false);
                                if (!ok) return;

                                state = SocksState.Authed;
                                if (_authOnce) AddAuthedIp(clientIp);
                                break;

                            case SocksState.Authed:
                                ConnectResult cr = await ConnectToTarget(buf, n)
                                    .ConfigureAwait(false);
                                if (cr.Error != SocksError.Success)
                                {
                                    await SendSocksReply(stream, cr.Error)
                                        .ConfigureAwait(false);
                                    return;
                                }

                                using (cr.Remote)
                                {
                                    await SendSocksReply(stream, SocksError.Success)
                                        .ConfigureAwait(false);
                                    Log.Info("client {0}: connected to {1}",
                                        clientIp, cr.Target);
                                    await RelayAsync(stream, cr.Remote.GetStream(), ct)
                                        .ConfigureAwait(false);
                                }
                                return;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // silently drop — matches C version behavior
            }
        }

        private AuthMethod CheckAuthMethod(byte[] buf, int n, string clientIp)
        {
            if (n < 2 || buf[0] != 0x05) return AuthMethod.Invalid;

            int nmethods = buf[1];
            if (n < 2 + nmethods) return AuthMethod.Invalid;

            bool hasNoAuth = false;
            bool hasUsername = false;

            for (int i = 0; i < nmethods; i++)
            {
                byte m = buf[2 + i];
                if (m == (byte)AuthMethod.NoAuth) hasNoAuth = true;
                if (m == (byte)AuthMethod.Username) hasUsername = true;
            }

            if (hasNoAuth)
            {
                if (_authUser == null) return AuthMethod.NoAuth;
                if (_authOnce && IsAuthedIp(clientIp)) return AuthMethod.NoAuth;
            }
            if (hasUsername && _authUser != null) return AuthMethod.Username;

            return AuthMethod.Invalid;
        }

        private bool CheckCredentials(byte[] buf, int n)
        {
            if (n < 5 || buf[0] != 0x01) return false;

            int ulen = buf[1];
            if (n < 2 + ulen + 1) return false;

            int plen = buf[2 + ulen];
            if (n < 2 + ulen + 1 + plen) return false;

            string user = Encoding.ASCII.GetString(buf, 2, ulen);
            string pass = Encoding.ASCII.GetString(buf, 2 + ulen + 1, plen);

            return user == _authUser && pass == _authPass;
        }

        private async Task<ConnectResult> ConnectToTarget(byte[] buf, int n)
        {
            ConnectResult fail;
            fail.Remote = null;
            fail.Target = null;

            if (n < 5)             { fail.Error = SocksError.GeneralFailure; return fail; }
            if (buf[0] != 0x05)    { fail.Error = SocksError.GeneralFailure; return fail; }
            if (buf[1] != 0x01)    { fail.Error = SocksError.CommandNotSupported; return fail; }
            if (buf[2] != 0x00)    { fail.Error = SocksError.GeneralFailure; return fail; }

            string host;
            int portOffset;

            switch (buf[3])
            {
                case 0x01: // IPv4
                    if (n < 10) { fail.Error = SocksError.GeneralFailure; return fail; }
                    host = new IPAddress(new byte[] {
                        buf[4], buf[5], buf[6], buf[7] }).ToString();
                    portOffset = 8;
                    break;

                case 0x04: // IPv6
                    if (n < 22) { fail.Error = SocksError.GeneralFailure; return fail; }
                    byte[] ipv6 = new byte[16];
                    Buffer.BlockCopy(buf, 4, ipv6, 0, 16);
                    host = new IPAddress(ipv6).ToString();
                    portOffset = 20;
                    break;

                case 0x03: // domain
                    int dlen = buf[4];
                    if (n < 4 + 1 + dlen + 2)
                        { fail.Error = SocksError.GeneralFailure; return fail; }
                    host = Encoding.ASCII.GetString(buf, 5, dlen);
                    portOffset = 5 + dlen;
                    break;

                default:
                    fail.Error = SocksError.AddressTypeNotSupported;
                    return fail;
            }

            int port = (buf[portOffset] << 8) | buf[portOffset + 1];

            try
            {
                TcpClient remote = new TcpClient();
                remote.NoDelay = true;

                if (_bindMode && _bindEndPoint != null)
                    remote.Client.Bind(new IPEndPoint(_bindEndPoint.Address, 0));

                await remote.ConnectAsync(host, port).ConfigureAwait(false);

                ConnectResult ok;
                ok.Remote = remote;
                ok.Error = SocksError.Success;
                ok.Target = string.Format("{0}:{1}", host, port);
                return ok;
            }
            catch (SocketException ex)
            {
                fail.Error = MapSocketError(ex.SocketErrorCode);
                return fail;
            }
        }

        private static SocksError MapSocketError(SocketError err)
        {
            switch (err)
            {
                case SocketError.TimedOut:
                    return SocksError.TtlExpired;
                case SocketError.ConnectionRefused:
                    return SocksError.ConnectionRefused;
                case SocketError.NetworkUnreachable:
                    return SocksError.NetworkUnreachable;
                case SocketError.HostUnreachable:
                    return SocksError.HostUnreachable;
                case SocketError.AddressFamilyNotSupported:
                case SocketError.ProtocolNotSupported:
                    return SocksError.AddressTypeNotSupported;
                default:
                    return SocksError.GeneralFailure;
            }
        }

        private static async Task RelayAsync(NetworkStream a, NetworkStream b,
                                              CancellationToken ct)
        {
            using (CancellationTokenSource timeoutCts =
                CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeoutCts.CancelAfter(TimeSpan.FromMinutes(15));

                Task t1 = CopyDirection(a, b, timeoutCts);
                Task t2 = CopyDirection(b, a, timeoutCts);

                await Task.WhenAny(t1, t2).ConfigureAwait(false);
                timeoutCts.Cancel();

                try { await Task.WhenAll(t1, t2).ConfigureAwait(false); }
                catch (OperationCanceledException) { }
                catch (System.IO.IOException) { }
            }
        }

        private static async Task CopyDirection(NetworkStream from, NetworkStream to,
                                                  CancellationTokenSource timeoutCts)
        {
            byte[] buf = new byte[1024];
            while (true)
            {
                timeoutCts.CancelAfter(TimeSpan.FromMinutes(15));

                int n = await from.ReadAsync(buf, 0, buf.Length, timeoutCts.Token)
                    .ConfigureAwait(false);
                if (n <= 0) break;

                await to.WriteAsync(buf, 0, n, timeoutCts.Token)
                    .ConfigureAwait(false);
                await to.FlushAsync(timeoutCts.Token)
                    .ConfigureAwait(false);
            }
        }

        private static async Task SendAuthResponse(NetworkStream s,
                                                     byte version, byte method)
        {
            byte[] resp = new byte[] { version, method };
            await s.WriteAsync(resp, 0, 2).ConfigureAwait(false);
            await s.FlushAsync().ConfigureAwait(false);
        }

        private static async Task SendSocksReply(NetworkStream s, SocksError err)
        {
            byte[] resp = new byte[] {
                0x05, (byte)err, 0x00, 0x01,
                0, 0, 0, 0,
                0, 0
            };
            await s.WriteAsync(resp, 0, 10).ConfigureAwait(false);
            await s.FlushAsync().ConfigureAwait(false);
        }

        private bool IsAuthedIp(string ip)
        {
            if (_authedIps == null) return false;
            lock (_authLock)
            {
                return _authedIps.Contains(ip);
            }
        }

        private void AddAuthedIp(string ip)
        {
            if (_authedIps == null) return;
            lock (_authLock)
            {
                _authedIps.Add(ip);
            }
        }
    }

    class Program
    {
        static int Main(string[] args)
        {
            string listenIp = "0.0.0.0";
            int port = 1080;
            string user = null;
            string pass = null;
            bool bindMode = false;
            bool authOnce = false;
            bool quiet = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-i":
                        if (i + 1 >= args.Length) return Usage();
                        listenIp = args[++i];
                        break;
                    case "-p":
                        if (i + 1 >= args.Length) return Usage();
                        port = int.Parse(args[++i]);
                        break;
                    case "-u":
                        if (i + 1 >= args.Length) return Usage();
                        user = args[i + 1];
                        args[i + 1] = new string('\0', args[i + 1].Length);
                        i++;
                        break;
                    case "-P":
                        if (i + 1 >= args.Length) return Usage();
                        pass = args[i + 1];
                        args[i + 1] = new string('\0', args[i + 1].Length);
                        i++;
                        break;
                    case "-b":
                        bindMode = true;
                        break;
                    case "-1":
                        authOnce = true;
                        break;
                    case "-q":
                        quiet = true;
                        break;
                    default:
                        return Usage();
                }
            }

            if ((user != null) != (pass != null))
            {
                Console.Error.WriteLine("error: user and pass must be used together");
                return 1;
            }
            if (authOnce && pass == null)
            {
                Console.Error.WriteLine(
                    "error: auth-once option must be used together with user/pass");
                return 1;
            }

            Log.Quiet = quiet;

            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                cts.Cancel();
            };

            SocksServer server = new SocksServer(
                listenIp, port, user, pass, bindMode, authOnce);

            try
            {
                server.RunAsync(cts.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                // clean shutdown
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("fatal: " + ex.Message);
                return 1;
            }

            return 0;
        }

        static int Usage()
        {
            Console.Error.WriteLine(
                "socksd SOCKS5 Server\n" +
                "--------------------\n" +
                "usage: socksd -1 -q -b -i listenip -p port -u user -P password\n" +
                "all arguments are optional.\n" +
                "by default listenip is 0.0.0.0 and port 1080.\n\n" +
                "option -q activates quiet mode: suppress all log output\n" +
                "option -b forces outgoing connections to be bound to the ip " +
                "specified with -i\n" +
                "option -1 activates auth_once mode: once a specific ip address\n" +
                "authed successfully with user/pass, it is added to a whitelist\n" +
                "and may use the proxy without auth.\n" +
                "this is handy for programs like firefox that don't support\n" +
                "user/pass auth. for it to work you'd basically make one connection\n" +
                "with another program that supports it, and then you can use " +
                "firefox too.\n");
            return 1;
        }
    }
}
