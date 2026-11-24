using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("Secwiz VM Setup")]
[assembly: AssemblyProduct("Secwiz VM")]
[assembly: AssemblyCompany("Secwizt Private Limited")]
[assembly: AssemblyCopyright("Copyright 2026 Secwizt Private Limited")]

internal sealed class Setup
{
    private const string Product = "Secwiz VM";
    private const string Publisher = "Secwizt Private Limited";
    private const string Uninstaller = "Uninstall.exe";
    private const string App = "svm-app.exe";
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\SecwizVM";
    // Every payload file is embedded, listed in payload.sha256, verified on install and removed on
    // uninstall. Keep this list in step with $binaries and $documents in build.ps1.
    private static readonly string[] Payload = { App, "svmd.exe", "svm.exe", "VERSION.txt",
        "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.md", "THIRD-PARTY-LICENSES.txt" };
    private static readonly string[] Installed = Payload.Concat(new[] { Uninstaller }).ToArray();
    private static readonly Assembly Package = typeof(Setup).Assembly;
    private static readonly string Executable = Package.Location;
    private static readonly string Temp = Path.GetTempPath();
    private static readonly string LogPath = Path.Combine(Temp, "secwizvm-setup.log");
    private static readonly StringComparison IgnoreCase = StringComparison.OrdinalIgnoreCase;

    private readonly string destination;
    private readonly string testRegistration;
    private readonly string[] shortcuts;
    private readonly bool testing;

    private Setup(string testFolder)
    {
        testing = testFolder != null;
        string shortcutRoot = null;
        if (testing)
        {
            if (!Path.IsPathRooted(testFolder))
                throw new ArgumentException("Use an absolute test folder with /D.");
            destination = Path.GetFullPath(testFolder).TrimEnd(Path.DirectorySeparatorChar);
            string tempRoot = Temp.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!destination.StartsWith(tempRoot, IgnoreCase) ||
                String.Equals(Path.GetDirectoryName(destination) + Path.DirectorySeparatorChar, tempRoot, IgnoreCase))
                throw new ArgumentException("Use a dedicated test folder inside a child folder of the Windows temporary folder.");
            shortcutRoot = destination + ".setup-test-shortcuts";
            testRegistration = destination + ".setup-test-registration";
        }
        else
        {
            destination = Path.Combine(KnownFolder(Environment.SpecialFolder.LocalApplicationData), "Programs", Product);
        }

        shortcuts = new[] {
            Path.Combine(testing ? Path.Combine(shortcutRoot, "Desktop") : KnownFolder(Environment.SpecialFolder.DesktopDirectory), Product + ".lnk"),
            Path.Combine(testing ? Path.Combine(shortcutRoot, "Start Menu") : KnownFolder(Environment.SpecialFolder.Programs), Product + ".lnk")
        };
    }

    [STAThread]
    private static int Main(string[] args)
    {
        bool quiet = args.Any(arg => String.Equals(arg, "/S", IgnoreCase));
        bool uninstall = args.Any(arg => String.Equals(arg, "/UNINSTALL", IgnoreCase));
        try
        {
            string testFolder = null;
            if (args.Length == 1 && args[0] == "/WORKER")
            {
                if (!String.Equals(Executable, Environment.GetEnvironmentVariable("SECWIZVM_SETUP_WORKER"), IgnoreCase))
                    throw new ArgumentException("Start the uninstaller from Installed apps.");
                quiet = Environment.GetEnvironmentVariable("SECWIZVM_SETUP_QUIET") == "1";
                uninstall = true;
                testFolder = Environment.GetEnvironmentVariable("SECWIZVM_SETUP_TEST");
                WaitForLauncher();
            }
            else
            {
                foreach (string arg in args)
                {
                    if (String.Equals(arg, "/S", IgnoreCase) || String.Equals(arg, "/UNINSTALL", IgnoreCase))
                        continue;
                    if (quiet && testFolder == null && arg.StartsWith("/D=", IgnoreCase))
                        testFolder = arg.Substring(3);
                    else
                        throw new ArgumentException("Use /S for quiet mode. /D is available only for quiet tests.");
                }
            }

            var setup = new Setup(testFolder);
            if (String.Equals(Executable, Path.Combine(setup.destination, Uninstaller), IgnoreCase))
            {
                setup.StartUninstallWorker(quiet);
                return 0;
            }

            if (!quiet)
            {
                string prompt = uninstall ? "Uninstall Secwiz VM? Your machines and data will stay on this PC."
                    : "Install Secwiz VM for your Windows account?";
                if (MessageBox.Show(prompt + "\n\nPublished by " + Publisher + ".", Product,
                        MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
                    return 0;
            }

            using (var gate = new Mutex(false, @"Global\SecwizVM.Setup." + PathId(setup.destination)))
            {
                bool acquired;
                try { acquired = gate.WaitOne(0); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new InvalidOperationException("Secwiz VM setup is already working on this folder.");
                try
                {
                    Log((uninstall ? "Uninstall started: " : "Install started: ") + setup.destination);
                    RequireStopped();
                    CheckPlainPath(setup.destination);
                    if (setup.testing)
                        foreach (string shortcut in setup.shortcuts) CheckPlainPath(Path.GetDirectoryName(shortcut));
                    setup.RecoverPreviousInstall();
                    if (uninstall) setup.Remove();
                    else setup.Install();
                    Log(uninstall ? "Uninstall completed." : "Install completed.");
                }
                finally { gate.ReleaseMutex(); }
            }

            if (!quiet)
                MessageBox.Show(uninstall ? "Secwiz VM was uninstalled. Your machines and data were kept."
                    : "Secwiz VM is ready. Open it from Start or the Desktop.", Product,
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception error)
        {
            Log("ERROR: " + error.Message);
            if (!quiet)
                MessageBox.Show(error.Message + "\n\nSetup log: " + LogPath, Product,
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private void Install()
    {
        string stage = destination + ".setup-stage-" + Guid.NewGuid().ToString("N");
        string previous = destination + ".setup-previous";
        var createdShortcuts = new List<string>();
        var registration = ReadRegistration();
        bool published = false;
        bool registrationStarted = false;

        CheckPackageFolder(destination);
        CheckShortcuts();
        Directory.CreateDirectory(stage);
        try
        {
            Dictionary<string, string> hashes = ReadHashes();
            foreach (string name in Payload)
            {
                string file = Path.Combine(stage, name);
                using (Stream resource = OpenResource(name))
                using (var output = new FileStream(file, FileMode.CreateNew, FileAccess.Write))
                {
                    resource.CopyTo(output);
                    output.Flush(true);
                }
                Verify(file, hashes[name]);
            }
            string uninstaller = Path.Combine(stage, Uninstaller);
            File.Copy(Executable, uninstaller);
            Verify(uninstaller, HashFile(Executable));
            string version = File.ReadAllText(Path.Combine(stage, "VERSION.txt")).Trim();
            if (version.Length == 0) throw new InvalidDataException("The setup package has no version.");

            RequireStopped();
            if (Directory.Exists(destination)) Directory.Move(destination, previous);
            Directory.Move(stage, destination);
            published = true;
            Log("Published the verified program folder.");
            foreach (string shortcut in shortcuts)
            {
                if (File.Exists(shortcut)) continue;
                CreateShortcut(shortcut);
                createdShortcuts.Add(shortcut);
                Log("Created shortcut: " + shortcut);
            }

            string command = Quote(Path.Combine(destination, Uninstaller)) + " /UNINSTALL";
            string testArgument = testing ? " " + Quote("/D=" + destination) : "";
            int estimatedSize = (int)(Installed.Sum(name => new FileInfo(Path.Combine(destination, name)).Length) / 1024);
            var values = new Dictionary<string, object> {
                { "DisplayName", Product },
                { "Publisher", Publisher },
                { "DisplayVersion", version },
                { "InstallLocation", destination },
                { "DisplayIcon", Quote(Path.Combine(destination, App)) },
                { "UninstallString", command + (testing ? " /S" + testArgument : "") },
                { "QuietUninstallString", command + " /S" + testArgument },
                { "EstimatedSize", estimatedSize },
                { "NoModify", 1 },
                { "NoRepair", 1 }
            };
            registrationStarted = true;
            WriteRegistration(values.ToDictionary(item => item.Key, item => Tuple.Create(
                item.Value, item.Value is int ? RegistryValueKind.DWord : RegistryValueKind.String)));
            Log(testing ? "Wrote the isolated uninstall test entry." : "Registered the per-user uninstall entry.");
        }
        catch
        {
            if (registrationStarted) TryCleanup(() => WriteRegistration(registration));
            foreach (string shortcut in createdShortcuts) TryCleanup(() => File.Delete(shortcut));
            if (published) Directory.Move(destination, stage);
            if (Directory.Exists(previous)) Directory.Move(previous, destination);
            throw;
        }
        finally { TryCleanup(() => DeletePackageFolder(stage)); }

        TryCleanup(() => DeletePackageFolder(previous));
    }

    private void Remove()
    {
        var registration = ReadRegistration();
        Dictionary<string, string> hashes = ReadHashes();
        hashes.Add(Uninstaller, HashFile(Executable));
        string stage = destination + ".setup-removal-" + Guid.NewGuid().ToString("N");
        var moved = new List<KeyValuePair<string, string>>();
        bool registrationStarted = false;
        try
        {
            RequireStopped();
            Directory.CreateDirectory(stage);
            foreach (string name in Installed)
            {
                string file = Path.Combine(destination, name);
                if (!File.Exists(file)) continue;
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0 ||
                    !String.Equals(HashFile(file), hashes[name], IgnoreCase))
                {
                    Log("Kept a changed file: " + file);
                    continue;
                }
                MoveForRemoval(file, Path.Combine(stage, name), moved);
                Log("Removed installed file: " + name);
            }
            foreach (string shortcut in shortcuts)
            {
                if (!IsAppShortcut(shortcut)) continue;
                MoveForRemoval(shortcut, shortcut + "." + Guid.NewGuid().ToString("N") + ".tmp", moved);
                Log("Removed shortcut: " + shortcut);
            }
            registrationStarted = true;
            WriteRegistration(null);
            Log(testing ? "Removed the isolated uninstall test entry." : "Removed the per-user uninstall entry.");
        }
        catch
        {
            if (registrationStarted) TryCleanup(() => WriteRegistration(registration));
            for (int index = moved.Count - 1; index >= 0; index--)
                File.Move(moved[index].Value, moved[index].Key);
            TryCleanup(() => DeleteIfEmpty(stage));
            throw;
        }
        foreach (var file in moved) TryCleanup(() => File.Delete(file.Value));
        TryCleanup(() => DeleteIfEmpty(stage));
        TryCleanup(() => DeleteIfEmpty(destination));
        if (testing)
        {
            foreach (string shortcut in shortcuts) TryCleanup(() => DeleteIfEmpty(Path.GetDirectoryName(shortcut)));
            TryCleanup(() => DeleteIfEmpty(destination + ".setup-test-shortcuts"));
        }
    }

    private static void MoveForRemoval(string source, string target, List<KeyValuePair<string, string>> moves)
    {
        File.Move(source, target);
        moves.Add(new KeyValuePair<string, string>(source, target));
    }

    private void RecoverPreviousInstall()
    {
        string previous = destination + ".setup-previous";
        if (!Directory.Exists(previous)) return;
        CheckPackageFolder(previous);
        if (Directory.Exists(destination))
        {
            CheckPackageFolder(destination);
            DeletePackageFolder(previous);
        }
        else Directory.Move(previous, destination);
        Log("Recovered a previous setup operation.");
    }

    private static void RequireStopped()
    {
        foreach (string name in new[] { "svm-app", "svmd" })
        {
            Process[] running = Process.GetProcessesByName(name);
            foreach (Process process in running) process.Dispose();
            if (running.Length != 0)
                throw new InvalidOperationException("Secwiz VM or its service is running. Close it before running setup again.");
        }
        Log("Secwiz VM and its service are stopped.");
    }

    private static void CheckPackageFolder(string directory)
    {
        CheckPlainPath(directory);
        if (!Directory.Exists(directory)) return;
        foreach (string entry in Directory.EnumerateFileSystemEntries(directory))
        {
            if (!Installed.Contains(Path.GetFileName(entry), StringComparer.OrdinalIgnoreCase) ||
                (File.GetAttributes(entry) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Setup found an extra file or folder in " + directory + ". Move it somewhere safe before upgrading.");
        }
    }

    private static void CheckPlainPath(string path)
    {
        for (string current = path; current != null; current = Path.GetDirectoryName(current))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != FileAttributes.Directory)
                throw new IOException("Setup needs a regular folder: " + current);
        }
    }

    private static void DeletePackageFolder(string directory)
    {
        if (!Directory.Exists(directory)) return;
        CheckPackageFolder(directory);
        foreach (string name in Installed) File.Delete(Path.Combine(directory, name));
        Directory.Delete(directory);
    }

    private static void DeleteIfEmpty(string directory)
    {
        if (Directory.Exists(directory) && !Directory.EnumerateFileSystemEntries(directory).Any())
            Directory.Delete(directory);
    }

    private void CheckShortcuts()
    {
        foreach (string shortcut in shortcuts)
            if (File.Exists(shortcut) && !IsAppShortcut(shortcut))
                throw new IOException("A different shortcut already uses the name Secwiz VM at " + shortcut + ".");
    }

    private bool IsAppShortcut(string path)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return false;
        return WithShortcut(path, link =>
            String.Equals((string)link.TargetPath, Path.Combine(destination, App), IgnoreCase) &&
            String.IsNullOrEmpty((string)link.Arguments));
    }

    private void CreateShortcut(string path)
    {
        string directory = Path.GetDirectoryName(path);
        Directory.CreateDirectory(directory);
        string temporary = Path.Combine(directory, ".secwizvm-" + Guid.NewGuid().ToString("N") + ".lnk");
        try
        {
            WithShortcut(temporary, link =>
            {
                link.TargetPath = Path.Combine(destination, App);
                link.WorkingDirectory = destination;
                link.Description = Product + " by " + Publisher;
                link.Save();
                return true;
            });
            File.Move(temporary, path);
        }
        finally { File.Delete(temporary); }
    }

    private static bool WithShortcut(string path, Func<dynamic, bool> action)
    {
        object shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell", true));
        try
        {
            object shortcut = ((dynamic)shell).CreateShortcut(path);
            try { return action(shortcut); }
            finally { Marshal.FinalReleaseComObject(shortcut); }
        }
        finally { Marshal.FinalReleaseComObject(shell); }
    }

    private Dictionary<string, Tuple<object, RegistryValueKind>> ReadRegistration()
    {
        Dictionary<string, Tuple<object, RegistryValueKind>> values;
        if (testing)
        {
            if (!File.Exists(testRegistration)) return null;
            if ((File.GetAttributes(testRegistration) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("The uninstall test entry needs to be a regular file.");
            values = File.ReadLines(testRegistration).Select(line => line.Split(new[] { '=' }, 2))
                .ToDictionary(fields => fields[0], fields => Tuple.Create((object)fields[1], RegistryValueKind.String));
        }
        else using (RegistryKey key = Registry.CurrentUser.OpenSubKey(UninstallKey))
        {
            if (key == null) return null;
            values = key.GetValueNames().ToDictionary(name => name, name => Tuple.Create(
                key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames), key.GetValueKind(name)));
        }
        Tuple<object, RegistryValueKind> location;
        if (!values.TryGetValue("InstallLocation", out location) ||
            !String.Equals(location.Item1 as string, destination, IgnoreCase))
            throw new IOException("The uninstall entry points to another folder.");
        return values;
    }

    private void WriteRegistration(Dictionary<string, Tuple<object, RegistryValueKind>> values)
    {
        // /D keeps registration and both shortcuts inside the test folder's parent.
        if (testing)
        {
            if (values == null) File.Delete(testRegistration);
            else
            {
                string temporary = testRegistration + "." + Guid.NewGuid().ToString("N");
                string previous = temporary + ".previous";
                try
                {
                    File.WriteAllLines(temporary, values.Select(item =>
                        item.Key + "=" + Convert.ToString(item.Value.Item1, CultureInfo.InvariantCulture)));
                    if (File.Exists(testRegistration)) File.Move(testRegistration, previous);
                    try { File.Move(temporary, testRegistration); }
                    catch
                    {
                        if (File.Exists(previous)) File.Move(previous, testRegistration);
                        throw;
                    }
                    TryCleanup(() => File.Delete(previous));
                }
                finally { File.Delete(temporary); }
            }
        }
        else if (values == null) Registry.CurrentUser.DeleteSubKey(UninstallKey, false);
        else
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(UninstallKey))
            {
                foreach (string name in key.GetValueNames())
                    if (!values.ContainsKey(name)) key.DeleteValue(name, false);
                foreach (var value in values) key.SetValue(value.Key, value.Value.Item1, value.Value.Item2);
            }
        }
    }

    private void StartUninstallWorker(bool quiet)
    {
        // Run outside the program folder so Windows can remove the installed executable.
        string copy = Path.Combine(Temp, "secwizvm-uninstall-" + Guid.NewGuid().ToString("N") + ".exe");
        File.Copy(Executable, copy);
        try
        {
            var launch = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                "/D /V:OFF /C start \"\" /wait \"%SECWIZVM_SETUP_WORKER%\" /WORKER & del /q \"%SECWIZVM_SETUP_WORKER%\"");
            launch.UseShellExecute = false;
            launch.CreateNoWindow = true;
            launch.EnvironmentVariables["SECWIZVM_SETUP_WORKER"] = copy;
            launch.EnvironmentVariables["SECWIZVM_SETUP_PARENT"] = Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture);
            launch.EnvironmentVariables["SECWIZVM_SETUP_QUIET"] = quiet ? "1" : "0";
            launch.EnvironmentVariables.Remove("SECWIZVM_SETUP_TEST");
            if (testing) launch.EnvironmentVariables["SECWIZVM_SETUP_TEST"] = destination;
            using (Process worker = Process.Start(launch))
                if (worker == null) throw new IOException("The uninstaller could not start.");
        }
        catch
        {
            TryCleanup(() => File.Delete(copy));
            throw;
        }
    }

    private static void WaitForLauncher()
    {
        int id = Int32.Parse(Environment.GetEnvironmentVariable("SECWIZVM_SETUP_PARENT"), CultureInfo.InvariantCulture);
        try
        {
            using (Process parent = Process.GetProcessById(id))
                if (!parent.WaitForExit(15000))
                    throw new IOException("The uninstaller did not finish starting. Try again.");
        }
        catch (ArgumentException) { /* The launcher already exited. */ }
    }

    private static Stream OpenResource(string name)
    {
        Stream stream = Package.GetManifestResourceStream(name);
        if (stream == null) throw new InvalidDataException("Setup is missing " + name + ".");
        return stream;
    }

    private static Dictionary<string, string> ReadHashes()
    {
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var reader = new StreamReader(OpenResource("payload.sha256")))
        {
            for (string line = reader.ReadLine(); line != null; line = reader.ReadLine())
            {
                string[] fields = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length != 2 || fields[0].Length != 64 || !fields[0].All(Uri.IsHexDigit) ||
                    !Payload.Contains(fields[1], StringComparer.OrdinalIgnoreCase) || hashes.ContainsKey(fields[1]))
                    throw new InvalidDataException("The setup package has an invalid checksum list.");
                hashes.Add(fields[1], fields[0]);
            }
        }
        if (hashes.Count != Payload.Length)
            throw new InvalidDataException("The setup package has an incomplete checksum list.");
        return hashes;
    }

    private static void Verify(string file, string expected)
    {
        if (!String.Equals(HashFile(file), expected, IgnoreCase))
            throw new InvalidDataException("The SHA-256 check failed for " + Path.GetFileName(file) + ".");
        Log("Verified SHA-256: " + Path.GetFileName(file));
    }

    private static string HashFile(string file)
    {
        using (SHA256 hash = SHA256.Create())
        using (FileStream input = File.OpenRead(file))
            return Hex(hash.ComputeHash(input));
    }

    private static string PathId(string path)
    {
        using (SHA256 hash = SHA256.Create())
            return Hex(hash.ComputeHash(Encoding.UTF8.GetBytes(path.ToUpperInvariant())));
    }

    private static string Hex(byte[] data) { return BitConverter.ToString(data).Replace("-", ""); }
    private static string Quote(string text) { return "\"" + text + "\""; }
    private static string KnownFolder(Environment.SpecialFolder folder)
    {
        string path = Environment.GetFolderPath(folder, Environment.SpecialFolderOption.DoNotVerify);
        if (String.IsNullOrEmpty(path)) throw new IOException("Windows could not find the " + folder + " folder.");
        return path;
    }

    private static void TryCleanup(Action action)
    {
        try { action(); }
        catch (Exception error) { Log("Cleanup needs attention: " + error.Message); }
    }

    private static void Log(string message)
    {
        try { File.AppendAllText(LogPath, DateTimeOffset.Now.ToString("o") + " " + message + Environment.NewLine); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
