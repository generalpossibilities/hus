mod rawverify;
const VK: &[u8] = include_bytes!("../../../../vectors/vk_raw.bin");
const GOOD: &[u8] = include_bytes!("../../../../vectors/good_raw.bin");
#[no_mangle]
pub extern "C" fn run(stage: u32) -> u32 { rawverify::verify_stage(VK, GOOD, stage as u8) as u32 }
