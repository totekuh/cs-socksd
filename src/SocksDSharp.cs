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
        private readonly SemaphoreSlim _connGate;
        private readonly int _timeoutMin;
        private IPEndPoint _bindEndPoint;

        public SocksServer(string listenIp, int port, string user, string pass,
                           bool bindMode, bool authOnce, int maxConn, int timeoutMin)
        {
            _listenIp = listenIp;
            _port = port;
            _authUser = user;
            _authPass = pass;
            _bindMode = bindMode;
            _authOnce = authOnce;
            _timeoutMin = timeoutMin > 0 ? timeoutMin : 15;
            if (authOnce) _authedIps = new HashSet<string>();
            if (maxConn > 0) _connGate = new SemaphoreSlim(maxConn, maxConn);
        }

        public async Task RunAsync(CancellationToken ct)
        {
            var listener = new TcpListener(IPAddress.Parse(_listenIp), _port);
            listener.Server.SetSocketOption(
                SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Start();

            try
            {
                Log.Info("socksd {0} listening on {1}:{2}",
                    Program.Version, _listenIp, _port);

                if (_bindMode)
                    _bindEndPoint = new IPEndPoint(IPAddress.Parse(_listenIp), 0);

                using (ct.Register(delegate { listener.Stop(); }))
                {
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
                            if (ct.IsCancellationRequested) break;
                            continue;
                        }
                    }
                }
            }
            finally
            {
                listener.Stop();
            }
        }

        private async void HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            bool gateAcquired = false;
            try
            {
                if (_connGate != null)
                {
                    await _connGate.WaitAsync(ct).ConfigureAwait(false);
                    gateAcquired = true;
                }

                using (client)
                using (CancellationTokenSource hsCts =
                    CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    hsCts.CancelAfter(TimeSpan.FromSeconds(60));
                    CancellationToken hsToken = hsCts.Token;

                    client.NoDelay = true;
                    NetworkStream stream = client.GetStream();
                    byte[] buf = new byte[1024];
                    string clientIp = ((IPEndPoint)client.Client.RemoteEndPoint)
                        .Address.ToString();

                    SocksState state = SocksState.Connected;

                    while (true)
                    {
                        int n = await stream.ReadAsync(buf, 0, buf.Length, hsToken)
                            .ConfigureAwait(false);
                        if (n <= 0) break;

                        switch (state)
                        {
                            case SocksState.Connected:
                                if (buf[0] == 0x04)
                                {
                                    await HandleSocks4(stream, buf, n,
                                        clientIp, ct).ConfigureAwait(false);
                                    return;
                                }

                                AuthMethod am = CheckAuthMethod(buf, n, clientIp);
                                if (am == AuthMethod.NoAuth)
                                    state = SocksState.Authed;
                                else if (am == AuthMethod.Username)
                                    state = SocksState.NeedAuth;

                                await SendAuthResponse(stream, 0x05, (byte)am, hsToken)
                                    .ConfigureAwait(false);
                                if (am == AuthMethod.Invalid) return;
                                break;

                            case SocksState.NeedAuth:
                                bool ok = CheckCredentials(buf, n);
                                await SendAuthResponse(stream, 0x01,
                                    (byte)(ok ? 0x00 : 0x01), hsToken)
                                    .ConfigureAwait(false);
                                if (!ok) return;

                                state = SocksState.Authed;
                                if (_authOnce) AddAuthedIp(clientIp);
                                break;

                            case SocksState.Authed:
                                ConnectResult cr = await ConnectToTarget(buf, n, ct)
                                    .ConfigureAwait(false);
                                if (cr.Error != SocksError.Success)
                                {
                                    await SendSocksReply(stream, cr.Error, ct)
                                        .ConfigureAwait(false);
                                    return;
                                }

                                using (cr.Remote)
                                {
                                    await SendSocksReply(stream, SocksError.Success, ct)
                                        .ConfigureAwait(false);
                                    Log.Info("client {0}: connected to {1}",
                                        clientIp, cr.Target);
                                    await RelayAsync(stream, cr.Remote.GetStream(),
                                        ct, _timeoutMin).ConfigureAwait(false);
                                }
                                return;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // silently drop — matches C version behavior
                try { client.Close(); }
                catch (Exception) { }
            }
            finally
            {
                if (gateAcquired) _connGate.Release();
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

            return ConstantTimeEquals(user, _authUser)
                && ConstantTimeEquals(pass, _authPass);
        }

        private static bool ConstantTimeEquals(string a, string b)
        {
            if (a == null || b == null) return false;
            int diff = a.Length ^ b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private async Task HandleSocks4(NetworkStream stream, byte[] buf, int n,
                                         string clientIp, CancellationToken ct)
        {
            // SOCKS4: VER(1) CD(1) PORT(2) IP(4) USERID(var) NULL(1)
            if (n < 9 || buf[1] != 0x01)
            {
                await SendSocks4Reply(stream, false, ct).ConfigureAwait(false);
                return;
            }

            if (_authUser != null && !(_authOnce && IsAuthedIp(clientIp)))
            {
                Log.Info("client {0}: socks4 rejected (auth required)", clientIp);
                await SendSocks4Reply(stream, false, ct).ConfigureAwait(false);
                return;
            }

            int port = (buf[2] << 8) | buf[3];
            byte[] ip = new byte[] { buf[4], buf[5], buf[6], buf[7] };

            // skip userid (null-terminated)
            int i = 8;
            while (i < n && buf[i] != 0x00) i++;
            if (i >= n)
            {
                await SendSocks4Reply(stream, false, ct).ConfigureAwait(false);
                return;
            }

            string host;

            // SOCKS4a: IP = 0.0.0.x (x != 0) means domain follows userid null
            if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0)
            {
                int ds = i + 1;
                int de = ds;
                while (de < n && buf[de] != 0x00) de++;
                if (de >= n)
                {
                    await SendSocks4Reply(stream, false, ct).ConfigureAwait(false);
                    return;
                }
                host = Encoding.ASCII.GetString(buf, ds, de - ds);
            }
            else
            {
                host = new IPAddress(ip).ToString();
            }

            if (port < 1 || port > 65535)
            {
                await SendSocks4Reply(stream, false, ct).ConfigureAwait(false);
                return;
            }

            try
            {
                TcpClient remote = new TcpClient();
                remote.NoDelay = true;

                if (_bindMode && _bindEndPoint != null)
                    remote.Client.Bind(new IPEndPoint(_bindEndPoint.Address, 0));

                Task connectTask = remote.ConnectAsync(host, port);
                Task timeout = Task.Delay(TimeSpan.FromSeconds(30), ct);
                Task winner = await Task.WhenAny(connectTask, timeout)
                    .ConfigureAwait(false);

                if (winner != connectTask || connectTask.IsFaulted)
                {
                    remote.Close();
                    // observe the faulted task to prevent UnobservedTaskException
                    var ignored = connectTask.ContinueWith(
                        delegate(Task t) { var e = t.Exception; },
                        TaskContinuationOptions.OnlyOnFaulted);
                    ct.ThrowIfCancellationRequested();
                    await SendSocks4Reply(stream, false, ct).ConfigureAwait(false);
                    return;
                }

                using (remote)
                {
                    await SendSocks4Reply(stream, true, ct).ConfigureAwait(false);
                    Log.Info("client {0}: connected to {1}:{2} (socks4)",
                        clientIp, host, port);
                    await RelayAsync(stream, remote.GetStream(), ct, _timeoutMin)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception)
            {
                try { await SendSocks4Reply(stream, false, ct).ConfigureAwait(false); }
                catch (Exception) { }
            }
        }

        private static async Task SendSocks4Reply(NetworkStream s, bool granted,
                                                     CancellationToken ct)
        {
            byte[] resp = new byte[] {
                0x00, (byte)(granted ? 0x5A : 0x5B),
                0, 0, 0, 0, 0, 0
            };
            await s.WriteAsync(resp, 0, 8, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);
        }

        private async Task<ConnectResult> ConnectToTarget(byte[] buf, int n,
                                                              CancellationToken ct)
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

            if (port < 1 || port > 65535)
            {
                fail.Error = SocksError.ConnectionRefused;
                return fail;
            }

            TcpClient remote = null;
            try
            {
                remote = new TcpClient();
                remote.NoDelay = true;

                if (_bindMode && _bindEndPoint != null)
                    remote.Client.Bind(new IPEndPoint(_bindEndPoint.Address, 0));

                Task connectTask = remote.ConnectAsync(host, port);
                Task timeout = Task.Delay(TimeSpan.FromSeconds(30), ct);
                Task winner = await Task.WhenAny(connectTask, timeout).ConfigureAwait(false);

                if (winner != connectTask)
                {
                    remote.Close();
                    remote = null;
                    // observe the faulted task to prevent UnobservedTaskException
                    var ignored = connectTask.ContinueWith(
                        delegate(Task t) { var e = t.Exception; },
                        TaskContinuationOptions.OnlyOnFaulted);
                    // ct cancelled = clean shutdown; otherwise = real timeout
                    ct.ThrowIfCancellationRequested();
                    fail.Error = SocksError.TtlExpired;
                    return fail;
                }

                if (connectTask.IsFaulted)
                {
                    remote.Close();
                    remote = null;
                    SocketException sx = connectTask.Exception.InnerException as SocketException;
                    fail.Error = sx != null ? MapSocketError(sx.SocketErrorCode)
                                            : SocksError.GeneralFailure;
                    return fail;
                }

                ConnectResult ok;
                ok.Remote = remote;
                ok.Error = SocksError.Success;
                ok.Target = string.Format("{0}:{1}", host, port);
                return ok;
            }
            catch (OperationCanceledException)
            {
                if (remote != null) try { remote.Close(); } catch (Exception) { }
                throw;
            }
            catch (SocketException ex)
            {
                if (remote != null) try { remote.Close(); } catch (Exception) { }
                fail.Error = MapSocketError(ex.SocketErrorCode);
                return fail;
            }
            catch (Exception)
            {
                if (remote != null) try { remote.Close(); } catch (Exception) { }
                fail.Error = SocksError.GeneralFailure;
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
                                              CancellationToken ct, int timeoutMin)
        {
            using (CancellationTokenSource timeoutCts =
                CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeoutCts.CancelAfter(TimeSpan.FromMinutes(timeoutMin));

                Task t1 = CopyDirection(a, b, timeoutCts, timeoutMin);
                Task t2 = CopyDirection(b, a, timeoutCts, timeoutMin);

                await Task.WhenAny(t1, t2).ConfigureAwait(false);
                try { timeoutCts.Cancel(); }
                catch (AggregateException) { }

                // Force-close both streams so that any ReadAsync / WriteAsync
                // blocked inside the kernel is aborted immediately.  On .NET
                // Framework 4.x the CancellationToken alone cannot interrupt
                // an in-progress socket operation; closing the underlying
                // socket is the only reliable way to unblock it.  This
                // prevents orphaned relay tasks from hanging in CLOSE_WAIT
                // for minutes when the remote peer disappears.
                try { a.Close(); } catch (Exception) { }
                try { b.Close(); } catch (Exception) { }

                try { await Task.WhenAll(t1, t2).ConfigureAwait(false); }
                catch (OperationCanceledException) { }
                catch (System.IO.IOException) { }
                catch (SocketException) { }
                catch (ObjectDisposedException) { }
                catch (AggregateException) { }
            }
        }

        private static async Task CopyDirection(NetworkStream from, NetworkStream to,
                                                  CancellationTokenSource timeoutCts,
                                                  int timeoutMin)
        {
            byte[] buf = new byte[65536];
            while (true)
            {
                try { timeoutCts.CancelAfter(TimeSpan.FromMinutes(timeoutMin)); }
                catch (ObjectDisposedException) { break; }

                int n = await from.ReadAsync(buf, 0, buf.Length, timeoutCts.Token)
                    .ConfigureAwait(false);
                if (n <= 0) break;

                await to.WriteAsync(buf, 0, n, timeoutCts.Token)
                    .ConfigureAwait(false);
                await to.FlushAsync(timeoutCts.Token)
                    .ConfigureAwait(false);
            }
        }

        public async Task RunReverseAsync(string host, int port, CancellationToken ct)
        {
            if (_bindMode)
                _bindEndPoint = new IPEndPoint(IPAddress.Parse(_listenIp), 0);

            Log.Info("socksd {0} reverse mode -> {1}:{2}",
                Program.Version, host, port);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ReverseSession(host, port, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Log.Info("control: {0}, reconnecting in 5s", ex.Message);
                }

                await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            }
        }

        private async Task ReverseSession(string host, int port, CancellationToken ct)
        {
            using (TcpClient control = new TcpClient())
            {
                control.NoDelay = true;
                await ConnectWithTimeout(control, host, port, 30, ct)
                    .ConfigureAwait(false);

                NetworkStream cs = control.GetStream();
                await cs.WriteAsync(new byte[] { 0x01 }, 0, 1, ct)
                    .ConfigureAwait(false);
                await cs.FlushAsync(ct).ConfigureAwait(false);

                byte[] ack = new byte[1];
                int n = await cs.ReadAsync(ack, 0, 1, ct).ConfigureAwait(false);
                if (n != 1 || ack[0] != 0x01)
                    throw new Exception("handshake failed");

                Log.Info("control channel established");

                byte[] sig = new byte[1];
                while (!ct.IsCancellationRequested)
                {
                    n = await cs.ReadAsync(sig, 0, 1, ct).ConfigureAwait(false);
                    if (n <= 0) break;

                    if (sig[0] == 0x01)
                    {
                        TcpClient data = null;
                        try
                        {
                            data = new TcpClient();
                            data.NoDelay = true;
                            await ConnectWithTimeout(data, host, port, 30, ct)
                                .ConfigureAwait(false);

                            NetworkStream ds = data.GetStream();
                            await ds.WriteAsync(new byte[] { 0x02 }, 0, 1, ct)
                                .ConfigureAwait(false);
                            await ds.FlushAsync(ct).ConfigureAwait(false);

                            HandleClientAsync(data, ct);
                            data = null; // ownership transferred
                        }
                        catch (Exception ex)
                        {
                            if (!(ex is OperationCanceledException))
                                Log.Info("data channel failed: {0}", ex.Message);
                            if (data != null)
                                try { data.Close(); } catch (Exception) { }
                            if (ex is OperationCanceledException) throw;
                        }
                    }
                }
            }

            Log.Info("control channel lost");
        }

        private static async Task ConnectWithTimeout(TcpClient client, string host,
                                                       int port, int timeoutSec,
                                                       CancellationToken ct)
        {
            Task connectTask = client.ConnectAsync(host, port);
            Task timeout = Task.Delay(TimeSpan.FromSeconds(timeoutSec), ct);
            Task winner = await Task.WhenAny(connectTask, timeout).ConfigureAwait(false);

            if (winner != connectTask)
            {
                client.Close();
                // observe the faulted task to prevent UnobservedTaskException
                var ignored = connectTask.ContinueWith(
                    delegate(Task t) { var e = t.Exception; },
                    TaskContinuationOptions.OnlyOnFaulted);
                ct.ThrowIfCancellationRequested();
                throw new SocketException((int)SocketError.TimedOut);
            }

            if (connectTask.IsFaulted)
                connectTask.GetAwaiter().GetResult(); // rethrow original exception

            await connectTask.ConfigureAwait(false);
        }

        private static async Task SendAuthResponse(NetworkStream s,
                                                     byte version, byte method,
                                                     CancellationToken ct)
        {
            byte[] resp = new byte[] { version, method };
            await s.WriteAsync(resp, 0, 2, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);
        }

        private static async Task SendSocksReply(NetworkStream s, SocksError err,
                                                    CancellationToken ct)
        {
            byte[] resp = new byte[] {
                0x05, (byte)err, 0x00, 0x01,
                0, 0, 0, 0,
                0, 0
            };
            await s.WriteAsync(resp, 0, 10, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);
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
        internal const string Version = "1.0.2";

        static int Main(string[] args)
        {
            string listenIp = "0.0.0.0";
            int port = 1080;
            string user = null;
            string pass = null;
            bool bindMode = false;
            bool authOnce = false;
            bool quiet = false;
            int maxConn = 0;
            int timeout = 15;
            string reverseHost = null;
            int reversePort = 0;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-i":
                    case "--ip":
                        if (i + 1 >= args.Length) return Usage();
                        listenIp = args[++i];
                        IPAddress tmp;
                        if (!IPAddress.TryParse(listenIp, out tmp))
                        {
                            Console.Error.WriteLine(
                                "fatal: invalid IP address '{0}'", listenIp);
                            return 1;
                        }
                        break;
                    case "-p":
                    case "--port":
                        if (i + 1 >= args.Length) return Usage();
                        int p;
                        if (!int.TryParse(args[++i], out p) || p < 1 || p > 65535)
                        {
                            Console.Error.WriteLine("fatal: invalid port '{0}'", args[i]);
                            return 1;
                        }
                        port = p;
                        break;
                    case "-u":
                    case "--user":
                        if (i + 1 >= args.Length) return Usage();
                        user = new string(args[i + 1].ToCharArray());
                        ZeroString(args[i + 1]);
                        args[i + 1] = null;
                        i++;
                        break;
                    case "-P":
                    case "--pass":
                        if (i + 1 >= args.Length) return Usage();
                        pass = new string(args[i + 1].ToCharArray());
                        ZeroString(args[i + 1]);
                        args[i + 1] = null;
                        i++;
                        break;
                    case "-t":
                    case "--timeout":
                        if (i + 1 >= args.Length) return Usage();
                        int t;
                        if (!int.TryParse(args[++i], out t) || t < 1)
                        {
                            Console.Error.WriteLine("fatal: invalid timeout '{0}'", args[i]);
                            return 1;
                        }
                        timeout = t;
                        break;
                    case "-c":
                    case "--max-conn":
                        if (i + 1 >= args.Length) return Usage();
                        int mc;
                        if (!int.TryParse(args[++i], out mc) || mc < 1)
                        {
                            Console.Error.WriteLine("fatal: invalid max-conn '{0}'", args[i]);
                            return 1;
                        }
                        maxConn = mc;
                        break;
                    case "-R":
                    case "--reverse":
                        if (i + 1 >= args.Length) return Usage();
                        string rv = args[++i];
                        int colon = rv.LastIndexOf(':');
                        if (colon < 1)
                        {
                            Console.Error.WriteLine(
                                "fatal: invalid reverse target '{0}' (expected host:port)", rv);
                            return 1;
                        }
                        reverseHost = rv.Substring(0, colon);
                        int rp;
                        if (!int.TryParse(rv.Substring(colon + 1), out rp)
                            || rp < 1 || rp > 65535)
                        {
                            Console.Error.WriteLine(
                                "fatal: invalid reverse port in '{0}'", rv);
                            return 1;
                        }
                        reversePort = rp;
                        break;
                    case "-b":
                    case "--bind":
                        bindMode = true;
                        break;
                    case "-1":
                    case "--auth-once":
                        authOnce = true;
                        break;
                    case "-q":
                    case "--quiet":
                        quiet = true;
                        break;
                    case "-v":
                    case "--version":
                        Console.Error.WriteLine("socksd " + Version);
                        return 0;
                    case "-h":
                    case "--help":
                        return Usage();
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
                listenIp, port, user, pass, bindMode, authOnce, maxConn, timeout);

            try
            {
                if (reverseHost != null)
                    server.RunReverseAsync(reverseHost, reversePort, cts.Token)
                        .GetAwaiter().GetResult();
                else
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
                "usage: socksd [options]\n\n" +
                "options:\n" +
                "  -i, --ip <addr>      listen address (default: 0.0.0.0)\n" +
                "  -p, --port <port>    listen port (default: 1080)\n" +
                "  -u, --user <user>    username for SOCKS5 auth\n" +
                "  -P, --pass <pass>    password for SOCKS5 auth\n" +
                "  -t, --timeout <min>  idle timeout in minutes (default: 15)\n" +
                "  -c, --max-conn <n>   max concurrent connections (default: unlimited)\n" +
                "  -R, --reverse <h:p>  reverse-connect to listener at host:port\n" +
                "  -1, --auth-once      whitelist IP after first successful auth\n" +
                "  -b, --bind           bind outgoing connections to listen IP\n" +
                "  -q, --quiet          suppress all log output\n" +
                "  -v, --version        show version\n" +
                "  -h, --help           show this help message\n");
            return 1;
        }

        private static unsafe void ZeroString(string s)
        {
            if (s == null) return;
            fixed (char* p = s)
            {
                for (int j = 0; j < s.Length; j++)
                    p[j] = '\0';
            }
        }
    }
}
