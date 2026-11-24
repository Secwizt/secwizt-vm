# STDIN is the fake tool's own CONIN$ handle. Nothing is sent to the focused window.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class BackupTestInput {
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteConsoleInputW(
        IntPtr input, byte[] records, uint count, out uint written);
    public static void Enter() {
        // INPUT_RECORD with KEY_EVENT, key down, repeat 1, VK_RETURN and carriage return.
        byte[] record = new byte[20];
        record[0] = 1; record[4] = 1; record[8] = 1; record[10] = 13; record[14] = 13;
        uint written;
        if (!WriteConsoleInputW(GetStdHandle(-10), record, 1, out written) || written != 1)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
}
"@
[BackupTestInput]::Enter()
