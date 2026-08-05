if (-not ('FakeNetAcceptance.NativeConsoleStop' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace FakeNetAcceptance
{
    public static class NativeConsoleStop
    {
        private delegate bool HandlerRoutine(uint controlType);

        [DllImport("Kernel32", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(
            HandlerRoutine handler, bool add);

        private static HandlerRoutine handler;
        private static int registered;
        private static int requested;

        public static void Register()
        {
            if (Interlocked.CompareExchange(ref registered, 1, 0) != 0)
                throw new InvalidOperationException(
                    "Console stop handler is already registered.");

            handler = HandleControl;
            if (!SetConsoleCtrlHandler(handler, true))
            {
                int error = Marshal.GetLastWin32Error();
                handler = null;
                Interlocked.Exchange(ref registered, 0);
                throw new Win32Exception(
                    error, "SetConsoleCtrlHandler registration failed.");
            }
            Interlocked.Exchange(ref requested, 0);
        }

        public static bool ConsumeRequested()
        {
            return Interlocked.Exchange(ref requested, 0) != 0;
        }

        public static void RequestForTest()
        {
            Interlocked.Exchange(ref requested, 1);
        }

        public static void Unregister()
        {
            if (Interlocked.CompareExchange(ref registered, 0, 1) == 0)
                return;

            HandlerRoutine current = handler;
            if (!SetConsoleCtrlHandler(current, false))
            {
                int error = Marshal.GetLastWin32Error();
                Interlocked.Exchange(ref registered, 1);
                throw new Win32Exception(
                    error, "SetConsoleCtrlHandler removal failed.");
            }
            handler = null;
            Interlocked.Exchange(ref requested, 0);
        }

        private static bool HandleControl(uint controlType)
        {
            if (controlType != 0 && controlType != 1)
                return false;
            Interlocked.Exchange(ref requested, 1);
            return true;
        }
    }
}
'@
}

function Initialize-ConsoleStopSignal {
    [FakeNetAcceptance.NativeConsoleStop]::Register()
}

function Test-ConsoleStopRequested {
    return [FakeNetAcceptance.NativeConsoleStop]::ConsumeRequested()
}

function Request-ConsoleStopForTest {
    [FakeNetAcceptance.NativeConsoleStop]::RequestForTest()
}

function Remove-ConsoleStopSignal {
    [FakeNetAcceptance.NativeConsoleStop]::Unregister()
}
