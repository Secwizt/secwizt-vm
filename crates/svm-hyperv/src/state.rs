use svm_core::{engine::{EngineError, EngineResult, Thumbnail}, model::VmState};

/// Transitional guests conservatively retain CPU and RAM admission until they settle.
pub fn map_state(name: &str) -> EngineResult<VmState> {
    match name {
        "Off" | "OffCritical" => Ok(VmState::Off),
        "Saved" | "SavedCritical" | "FastSaved" | "FastSavedCritical" | "Hibernated" => Ok(VmState::Saved),
        "Paused" | "PausedCritical" => Ok(VmState::Paused),
        "Running" | "RunningCritical" | "Starting" | "StartingCritical" |
        "Stopping" | "StoppingCritical" | "Reset" | "ResetCritical" |
        "Saving" | "SavingCritical" | "FastSaving" | "FastSavingCritical" |
        "Pausing" | "PausingCritical" | "Resuming" | "ResumingCritical" |
        "ForceShutdown" | "ForceReboot" | "ComponentServicing" => Ok(VmState::Running),
        _ => Err(EngineError::Engine(format!("Hyper-V state '{name}' has no known core-state mapping."))),
    }
}

pub(crate) fn from_native(code: i32, symbol: Option<&str>) -> EngineResult<VmState> {
    // For extended/critical states the installed Hyper-V enum supplies its own name.
    // An undefined enum value stringifies as its number and must fail closed.
    let fixed = match code {
        2 => Some("Running"), 3 => Some("Off"), 4 => Some("Stopping"), 6 => Some("Saved"),
        9 => Some("Paused"), 10 => Some("Starting"), 11 => Some("Reset"), _ => None,
    };
    if let (Some(known), Some(reported)) = (fixed, symbol) {
        if known != reported {
            return Err(EngineError::Engine(format!("Inconsistent Hyper-V state {code} ({reported}).")));
        }
    }
    let name = symbol.or(fixed).ok_or_else(|| EngineError::Engine(format!("Unknown Hyper-V state {code}.")))?;
    map_state(name)
}

fn pixel_count(width: u16, height: u16) -> EngineResult<usize> {
    let count = usize::from(width) * usize::from(height);
    if count == 0 || count > 1024 * 1024 {
        return Err(EngineError::Engine("Invalid thumbnail dimensions.".into()));
    }
    Ok(count)
}

pub fn rgb565_to_rgba(width: u16, height: u16, bytes: &[u8]) -> EngineResult<Thumbnail> {
    let count = pixel_count(width, height)?;
    let required = count * 2;
    if bytes.len() != required && bytes.len() != required + 4 {
        return Err(EngineError::Engine("RGB565 thumbnail length does not match its dimensions.".into()));
    }
    let mut rgba = Vec::with_capacity(count * 4);
    for pair in bytes[..required].chunks_exact(2) {
        let word = u16::from_le_bytes([pair[0], pair[1]]);
        let r = ((word >> 11) & 31) as u8;
        let g = ((word >> 5) & 63) as u8;
        let b = (word & 31) as u8;
        rgba.extend_from_slice(&[(r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2), 255]);
    }
    Ok(Thumbnail { width, height, rgba })
}

pub(crate) fn decode_frame(width: u16, height: u16, hex: &str) -> EngineResult<Thumbnail> {
    let required = pixel_count(width, height)? * 4;
    if (hex.len() != required && hex.len() != required + 8) || !hex.is_ascii() {
        return Err(EngineError::Engine("Invalid thumbnail response length or encoding.".into()));
    }
    let mut bytes = Vec::with_capacity(hex.len()/2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2],16)
            .map_err(|_| EngineError::Engine("Invalid hexadecimal thumbnail data.".into()))?;
        bytes.push(byte);
    }
    rgb565_to_rgba(width, height, &bytes)
}
