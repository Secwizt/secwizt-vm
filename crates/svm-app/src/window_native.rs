use std::{
    env, io::Write, os::windows::process::CommandExt, path::{Path, PathBuf},
    process::{Command, Stdio}, thread, time::Duration,
};

const FORMS: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition @'
using System;
using System.Windows.Forms;
public sealed class SvmDialogOwner : IWin32Window {
    public IntPtr Handle { get; private set; }
    public SvmDialogOwner(long value) { Handle = new IntPtr(value); }
}
'@
[Windows.Forms.Application]::EnableVisualStyles()
$owner = [SvmDialogOwner]::new([long]$env:SVM_DIALOG_OWNER)
$title = 'Secwizt Virtual Machine'
function Write-GuestFileSelection([string]$path) {
    $drive = [IO.Path]::GetPathRoot($path)
    if ($drive.StartsWith('\\?\')) { $drive = $drive.Substring(4) }
    if ($drive -notmatch '^[A-Za-z]:\\$' -or ([IO.DriveInfo]::new($drive)).DriveType -notin 'Fixed','Removable','Ram') { exit 3 }
    [Console]::Write($path)
}
switch -Exact ($env:SVM_DIALOG_KIND) {
    'error' {
        [void][Windows.Forms.MessageBox]::Show($owner,$env:SVM_DIALOG_VALUE,$title,'OK','Error')
    }
    { $_ -in @('folder','backup-folder') } {
        $d = [Windows.Forms.FolderBrowserDialog]::new()
        try {
            $d.Description = if ($_ -eq 'backup-folder') { 'Choose a local folder for encrypted backups' } else { 'Choose a folder for the exported virtual disk' }
            $d.ShowNewFolderButton = $true
            if ($d.ShowDialog($owner) -eq 'OK') { [Console]::Write($d.SelectedPath) }
        } finally { $d.Dispose() }
    }
    'guest-download' {
        $d = [Windows.Forms.SaveFileDialog]::new()
        try {
            $d.Title = 'Save the file from the machine'
            $d.Filter = 'All files (*.*)|*.*'
            $d.AddExtension = $false
            $d.CheckPathExists = $true
            $d.OverwritePrompt = $false
            $d.RestoreDirectory = $true
            $d.FileName = $env:SVM_DIALOG_VALUE
            if ($d.ShowDialog($owner) -eq 'OK') { Write-GuestFileSelection $d.FileName }
        } finally { $d.Dispose() }
    }
    { $_ -in @('iso','qemu','disk','guest-upload','backup-file') } {
        $d = [Windows.Forms.OpenFileDialog]::new()
        try {
            if ($_ -in @('backup-file','guest-upload')) {
                $d.Title = if ($_ -eq 'backup-file') { 'Choose a file from your YubiKey backup setup' } else { 'Choose the file to send to the machine' }
                $d.Filter = 'All files (*.*)|*.*'
            } elseif ($_ -eq 'disk') {
                $d.Title = 'Choose a local virtual disk'
                $d.Filter = 'Virtual disks|*.vmdk;*.vdi;*.vhd;*.vhdx;*.qcow2;*.img'
            } elseif ($_ -eq 'qemu') {
                $d.Title = 'Choose the QEMU system executable'
                $d.Filter = 'QEMU system executable (qemu-system-x86_64.exe)|qemu-system-x86_64.exe'
            } else {
                $d.Title = 'Choose an installer image'
                $d.Filter = 'Installer images (*.iso)|*.iso'
            }
            $d.DereferenceLinks = $false
            $d.Multiselect = $false
            $d.CheckFileExists = $true
            $d.RestoreDirectory = $true
            if ($env:SVM_DIALOG_VALUE) { $d.InitialDirectory = $env:SVM_DIALOG_VALUE }
            if ($d.ShowDialog($owner) -eq 'OK') {
                if ($_ -in @('backup-file','guest-upload')) { Write-GuestFileSelection $d.FileName }
                else { [Console]::Write($d.FileName) }
            }
        } finally { $d.Dispose() }
    }
    'copy' { [Windows.Forms.Clipboard]::SetText($env:SVM_DIALOG_VALUE) }
    'menu' {
        $form = [Windows.Forms.Form]::new()
        try {
            $form.Text = 'App menu'
            $form.StartPosition = 'CenterParent'
            $form.FormBorderStyle = 'FixedDialog'
            $form.MinimizeBox = $false
            $form.MaximizeBox = $false
            $form.ClientSize = [Drawing.Size]::new(256,96)
            $strip = [Windows.Forms.MenuStrip]::new()
            $strip.Dock = 'Fill'
            $strip.LayoutStyle = 'VerticalStackWithOverflow'
            $stop = [Windows.Forms.ToolStripMenuItem]::new('&Stop the service')
            $cancel = [Windows.Forms.ToolStripMenuItem]::new('&Close menu')
            [void]$strip.Items.Add($stop)
            [void]$strip.Items.Add($cancel)
            $form.MainMenuStrip = $strip
            $form.Controls.Add($strip)
            $stop.Add_Click({
                $answer = [Windows.Forms.MessageBox]::Show($form,'Stop the service? Hyper-V guests keep running. QEMU guests power off if the service stays offline for ten minutes. Throwaway machines are reset only while the service runs. Save your work in those guests first.',$title,'YesNo','Question','Button2')
                if ($answer -eq 'Yes') { $form.Tag = 'stop' ; $form.Close() }
            })
            $cancel.Add_Click({ $form.Close() })
            $form.KeyPreview = $true
            $form.Add_KeyDown({ if ($_.KeyCode -eq 'Escape') { $form.Close() } })
            $form.Add_Shown({ [void]$strip.Focus(); $stop.Select() })
            [void]$form.ShowDialog($owner)
            if ($form.Tag -eq 'stop') { [Console]::Write('stop') }
        } finally { $form.Dispose() }
    }
    'close' {
        $form = [Windows.Forms.Form]::new()
        try {
            $form.Text = $title
            $form.StartPosition = 'CenterParent'
            $form.FormBorderStyle = 'FixedDialog'
            $form.MinimizeBox = $false
            $form.MaximizeBox = $false
            $form.AutoScaleMode = 'Dpi'
            $form.ClientSize = [Drawing.Size]::new(438,144)
            $message = [Windows.Forms.Label]::new()
            $message.SetBounds(16,14,406,42)
            $message.Text = 'Closing the last window stops the service when idle. Running, paused or unverified machines keep the service open.'
            $skip = [Windows.Forms.CheckBox]::new()
            $skip.SetBounds(16,62,310,26)
            $skip.Text = 'Do not show again'
            $accept = [Windows.Forms.Button]::new()
            $accept.Text = 'Close window'; $accept.SetBounds(164,102,132,30); $accept.DialogResult = 'OK'
            $back = [Windows.Forms.Button]::new()
            $back.Text = 'Cancel'; $back.SetBounds(304,102,116,30); $back.DialogResult = 'Cancel'
            $form.Controls.AddRange(@($message,$skip,$accept,$back))
            $form.AcceptButton = $accept; $form.CancelButton = $back
            if ($form.ShowDialog($owner) -eq 'OK') {
                if ($skip.Checked) { [Console]::Write('always') } else { [Console]::Write('close') }
            }
        } finally { $form.Dispose() }
    }
    default { exit 2 }
}
"#;

pub fn dialog(kind: &str, owner: isize, value: &str) -> Result<String,String> {
    let root = env::var_os("SystemRoot").ok_or("Cannot find the Windows installation.")?;
    let shell = PathBuf::from(root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let output = Command::new(shell).args(["-NoProfile","-NonInteractive","-STA","-Command",FORMS])
        .env("SVM_DIALOG_KIND", kind).env("SVM_DIALOG_OWNER", owner.to_string()).env("SVM_DIALOG_VALUE", value)
        .creation_flags(0x0800_0000).stdin(Stdio::null()).stderr(Stdio::null()).output()
        .map_err(|_| "Windows could not open the native dialog.")?;
    if matches!(kind, "guest-upload" | "guest-download" | "backup-file") && output.status.code() == Some(3) {
        return Err("Choose a file on a local drive.".into());
    }
    if !output.status.success() { return Err("Windows could not complete the requested desktop action.".into()); }
    String::from_utf8(output.stdout).map_err(|_| "Windows returned unreadable text.".to_owned())
}

pub(crate) const CLIPBOARD_TEXT_LIMIT: usize = 1024 * 1024;

const COPY_CLIPBOARD: &str = r#"
$ErrorActionPreference = 'Stop'
$inputPipe = [Console]::OpenStandardInput()
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$reader = [IO.StreamReader]::new($inputPipe, $utf8, $false)
try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
if (!$text -or $text.Contains([char]0) -or $utf8.GetByteCount($text) -gt 1048576) { exit 3 }
Add-Type -AssemblyName System.Windows.Forms
[Windows.Forms.Clipboard]::SetText($text, [Windows.Forms.TextDataFormat]::UnicodeText)
"#;

pub fn copy_console_text(text: String) -> Result<(), String> {
    if text.is_empty() || text.len() > CLIPBOARD_TEXT_LIMIT || text.contains('\0') {
        return Err("Choose plain clipboard text of up to 1 MiB.".into());
    }
    let failure = || "Windows could not copy the guest text. Try again.".to_owned();
    let root = PathBuf::from(env::var_os("SystemRoot").ok_or_else(failure)?);
    let shell = root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut child = Command::new(shell).current_dir(&root)
        .args(["-NoProfile", "-NonInteractive", "-STA", "-Command", COPY_CLIPBOARD])
        .creation_flags(0x0800_0000).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|_| failure())?;
    let mut input = child.stdin.take().expect("clipboard helper stdin");
    let writer = thread::spawn(move || input.write_all(text.as_bytes()));
    let result = svm_app::wait_for_viewer_helper(&mut child, Duration::from_secs(8)).map_err(|_| failure())?;
    let sent = writer.join().is_ok_and(|sent| sent.is_ok());
    if result.is_some_and(|status| status.success()) && sent { Ok(()) } else { Err(failure()) }
}

pub fn show_error(message: &str) {
    if dialog("error", 0, message).is_err() { eprintln!("{message}"); }
}

pub fn open_trash(home: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    let mut path = home.canonicalize().map_err(|_| "The data folder cannot be opened.")?;
    for name in ["library", "trash"] {
        path.push(name);
        let info = match std::fs::symlink_metadata(&path) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err("Library trash is empty.".into()),
            Err(_) => return Err("The library trash folder cannot be read.".into()),
        };
        if !info.is_dir() || info.file_attributes() & 0x400 != 0 {
            return Err("The library trash path must be a local directory inside the data folder.".into());
        }
    }
    open_folder(&path)
}

pub fn open_folder(home: &Path) -> Result<(),String> {
    let root = env::var_os("SystemRoot").ok_or("Cannot find the Windows installation.")?;
    let path = home.canonicalize().map_err(|_| "The data folder cannot be opened.")?;
    let path = path.to_str().ok_or("The data folder path is unreadable.")?;
    let display = path.strip_prefix(r"\\?\").unwrap_or(path);
    if display.starts_with(r"UNC\") || display.starts_with(r"\\") { return Err("Choose a local data folder.".into()); }
    Command::new(PathBuf::from(root).join("explorer.exe")).arg(display).stdin(Stdio::null())
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|_| "Windows could not open the data folder.")?;
    Ok(())
}
