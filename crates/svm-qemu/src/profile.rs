//! Hardware limits for the QEMU x86 profiles. Android keeps its fixed profile; ordinary
//! legacy-BIOS guests get a small range; imported BIOS disks keep the families accepted at import.

use svm_core::{engine::{EngineError, EngineResult}, model::{GuestArchitecture, GuestFamily}};

pub const MAX_VCPU: u16 = 4;
pub const MAX_RAM_GB: u32 = 8;

fn refuse(message: &str) -> EngineError { EngineError::Invalid(message.to_owned()) }

/// Checks family, CPU count and memory for a QEMU machine.
/// `imported` is true for a machine created from an imported BIOS disk.
pub fn validate_hardware(family: GuestFamily, imported: bool, vcpu: u16, ram_gb: u32) -> EngineResult<()> {
    validate_minimum_hardware(vcpu, ram_gb)?;
    match family {
        GuestFamily::Macos => return Err(refuse("macOS guests need Apple hardware and the Mac version of this app; they cannot run on QEMU here.")),
        GuestFamily::Android => {
            return if vcpu == 1 && ram_gb == 2 { Ok(()) }
                else { Err(refuse("The Android profile uses exactly 1 CPU and 2 GiB of memory.")) };
        }
        GuestFamily::Windows if !imported => return Err(refuse("New Windows machines use Hyper-V. Import an existing legacy Windows disk to run it on QEMU.")),
        GuestFamily::Dos if !imported => return Err(refuse("DOS is not in this profile yet; choose Other.")),
        GuestFamily::Windows | GuestFamily::Dos | GuestFamily::Linux | GuestFamily::Bsd | GuestFamily::Other => {}
    }
    validate_x86_limits(vcpu, ram_gb)
}

fn validate_minimum_hardware(vcpu: u16, ram_gb: u32) -> EngineResult<()> {
    if vcpu == 0 { return Err(refuse("A machine needs at least one CPU.")); }
    if ram_gb == 0 { return Err(refuse("A machine needs at least 1 GiB of memory.")); }
    Ok(())
}

fn validate_x86_limits(vcpu: u16, ram_gb: u32) -> EngineResult<()> {
    if vcpu > MAX_VCPU { return Err(refuse("This QEMU profile allows 1 to 4 CPUs.")); }
    if ram_gb > MAX_RAM_GB { return Err(refuse("This QEMU profile allows 1 to 8 GiB of memory.")); }
    Ok(())
}

/// Checks an explicitly selected BIOS Windows installation on x86 PC hardware.
pub fn validate_legacy_windows_profile(architecture: GuestArchitecture, family: GuestFamily, vcpu: u16, ram_gb: u32) -> EngineResult<()> {
    if architecture != GuestArchitecture::X86_64 || family != GuestFamily::Windows {
        return Err(refuse("Legacy BIOS installation requires Windows and x86 PC hardware."));
    }
    validate_minimum_hardware(vcpu, ram_gb)?;
    validate_x86_limits(vcpu, ram_gb)
}

pub fn validate_profile(architecture: GuestArchitecture, family: GuestFamily, imported: bool, vcpu: u16, ram_gb: u32) -> EngineResult<()> {
    if architecture == GuestArchitecture::X86_64 {
        return validate_hardware(family, imported, vcpu, ram_gb);
    }
    if imported || !matches!(family, GuestFamily::Linux | GuestFamily::Other) {
        return Err(refuse("Emulated Arm supports new Linux and Other machines."));
    }
    if !(1..=2).contains(&vcpu) || !(1..=4).contains(&ram_gb) {
        return Err(refuse("Emulated Arm allows 1 to 2 CPUs and 1 to 4 GiB of memory."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use GuestFamily::*;

    fn ok(f: GuestFamily, imported: bool, v: u16, r: u32) -> bool { validate_hardware(f, imported, v, r).is_ok() }
    fn why(f: GuestFamily, imported: bool, v: u16, r: u32) -> String {
        validate_hardware(f, imported, v, r).err().map(|e| e.to_string()).unwrap_or_default()
    }

    #[test]
    fn arm_accepts_only_explicit_new_linux_or_other_within_its_limits() {
        use svm_core::model::GuestArchitecture::Aarch64;
        for family in [Linux, Other] {
            for (cpus, ram) in [(1,1),(2,4)] { assert!(validate_profile(Aarch64,family,false,cpus,ram).is_ok()); }
            for (cpus, ram) in [(0,2),(3,2),(1,0),(2,5)] { assert!(validate_profile(Aarch64,family,false,cpus,ram).is_err()); }
            assert!(validate_profile(Aarch64,family,true,1,2).is_err());
        }
        for family in [Windows,Android,Bsd,Macos,Dos] { assert!(validate_profile(Aarch64,family,false,1,2).is_err()); }
    }

    #[test]
    fn new_legacy_windows_is_an_explicit_x86_profile() {
        use GuestArchitecture::{Aarch64, X86_64};
        assert!(validate_legacy_windows_profile(X86_64, Windows, 1, 2).is_ok());
        assert!(validate_profile(X86_64, Windows, false, 1, 2).is_err());
        assert!(validate_profile(X86_64, Windows, true, 1, 2).is_ok());
        assert!(validate_legacy_windows_profile(Aarch64, Windows, 1, 2).is_err());
        assert!(validate_legacy_windows_profile(X86_64, Linux, 1, 2).is_err());
        assert!(validate_legacy_windows_profile(X86_64, Windows, 0, 2).is_err());
        assert!(validate_legacy_windows_profile(X86_64, Windows, 1, 9).is_err());
    }

    #[test]
    fn android_keeps_its_fixed_profile_on_both_paths() {
        for imported in [false, true] {
            assert!(ok(Android, imported, 1, 2));
            for (v, r) in [(2, 2), (1, 1), (1, 4), (4, 8)] {
                assert!(why(Android, imported, v, r).contains("exactly 1 CPU"), "android {v}/{r} imported={imported}");
            }
        }
    }

    #[test]
    fn new_machines_allow_linux_bsd_other_within_the_range() {
        for f in [Linux, Bsd, Other] {
            for (v, r) in [(1, 1), (1, 8), (4, 1), (4, 8), (2, 2)] { assert!(ok(f, false, v, r), "{f:?} {v}/{r}"); }
            assert!(why(f, false, 5, 2).contains("1 to 4 CPUs"));
            assert!(why(f, false, 2, 9).contains("1 to 8 GiB"));
        }
        assert!(why(Windows, false, 2, 4).contains("use Hyper-V"));
        assert!(why(Dos, false, 1, 1).contains("choose Other"));
    }

    #[test]
    fn imported_disks_keep_the_families_accepted_at_import() {
        for f in [Linux, Bsd, Other, Dos, Windows] {
            assert!(ok(f, true, 1, 2), "{f:?} with the import default");
            assert!(ok(f, true, 4, 8), "{f:?} at the upper limit");
            assert!(!ok(f, true, 5, 2) && !ok(f, true, 1, 9), "{f:?} above the limit");
        }
    }

    #[test]
    fn macos_and_zero_values_are_always_refused() {
        for imported in [false, true] {
            assert!(why(Macos, imported, 1, 2).contains("Apple hardware"));
            for f in [Linux, Android, Windows, Bsd, Dos, Other, Macos] {
                assert!(why(f, imported, 0, 2).contains("at least one CPU"), "{f:?}");
                assert!(why(f, imported, 1, 0).contains("at least 1 GiB"), "{f:?}");
            }
        }
    }
}
