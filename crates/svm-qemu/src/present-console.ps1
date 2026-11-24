$ErrorActionPreference = 'Stop'
$worker = [Diagnostics.Process]::GetProcessById([int]$env:SVM_CONSOLE_PID)
# Keep the process object open while checking the HWND. The supervisor also holds its Child.
$null = $worker.Handle
$title = 'QEMU (svm-' + $env:SVM_CONSOLE_ID + ')'
$timer = [Diagnostics.Stopwatch]::StartNew()
do {
    $worker.Refresh()
    if ($worker.HasExited) { return }
    $window = $worker.MainWindowHandle
    if ($window -ne [IntPtr]::Zero -and $worker.MainWindowTitle.StartsWith($title, [StringComparison]::Ordinal)) { break }
    Start-Sleep -Milliseconds 40
} while ($timer.ElapsedMilliseconds -lt 2000)
if ($window -eq [IntPtr]::Zero -or !$worker.MainWindowTitle.StartsWith($title, [StringComparison]::Ordinal)) { return }

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class GuestConsole {
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] static extern bool ShowWindowAsync(IntPtr window, int command);
    public static bool RestoreIfMinimized(IntPtr window, uint expectedPid) {
        uint owner;
        if (GetWindowThreadProcessId(window, out owner) == 0 || owner != expectedPid || !IsIconic(window)) return false;
        // SW_SHOWNOACTIVATE restores the last normal size without requesting foreground focus.
        if (!ShowWindowAsync(window, 4)) throw new InvalidOperationException("The guest console could not be restored.");
        return true;
    }
}
"@
if ([GuestConsole]::RestoreIfMinimized($window, $worker.Id)) {
    $timer.Restart()
    while ([GuestConsole]::IsIconic($window) -and $timer.ElapsedMilliseconds -lt 1000) { Start-Sleep -Milliseconds 20 }
    if ([GuestConsole]::IsIconic($window)) { throw 'The guest console did not acknowledge its restored window state.' }
}
