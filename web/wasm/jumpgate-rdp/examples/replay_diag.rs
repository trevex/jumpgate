// Diagnostic: replay an rdp-graphics-v1 recording through the SAME ironrdp-session
// ActiveStage the WASM viewer uses, render to PNG, report per-frame decode errors
// and whether the final framebuffer is black. `cargo run --example replay_diag -- <file.rdpg>`
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::rdp::client_info::CompressionType;
use ironrdp_pdu::Action;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStageBuilder, ActiveStageOutput};
use ironrdp_svc::StaticChannelSet;

fn u16le(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o+1]]) }
fn u32le(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o],b[o+1],b[o+2],b[o+3]]) }

fn main() {
    let path = std::env::args().nth(1).expect("path to .rdpg");
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[0..4], b"RDPG", "bad magic");
    let width = u16le(&b,5); let height = u16le(&b,7);
    let user_channel_id = u16le(&b,9); let io_channel_id = u16le(&b,11);
    let message_channel_id = if b[13]==1 { Some(u16le(&b,14)) } else { None };
    let share_id = u32le(&b,16); let comp = b[20];
    let compression_type = match comp { 0=>None,1=>Some(CompressionType::K8),2=>Some(CompressionType::K64),3=>Some(CompressionType::Rdp6),4=>Some(CompressionType::Rdp61),_=>None };
    println!("Header {width}x{height} user={user_channel_id} io={io_channel_id} msg={message_channel_id:?} share=0x{share_id:x} comp={comp} esp={} psr={}", b[21], b[22]);
    let mut image = DecodedImage::new(PixelFormat::RgbA32, width, height);
    let mut stage = ActiveStageBuilder{ static_channels: StaticChannelSet::new(), user_channel_id, io_channel_id, message_channel_id, share_id, compression_type, enable_server_pointer: b[21]!=0, pointer_software_rendering: b[22]!=0 }.build();
    let mut o = 23usize; let (mut n, mut errs, mut graphics_updates) = (0u32,0u32,0u32);
    while o + 13 <= b.len() {
        let action = b[o+8]; let len = u32le(&b, o+9) as usize; o += 13;
        if o+len > b.len() { break; }
        let payload = &b[o..o+len]; o += len; n += 1;
        let act = if action==0 { Action::FastPath } else { Action::X224 };
        match stage.process(&mut image, act, payload) {
            Ok(outs) => for out in outs { if matches!(out, ActiveStageOutput::GraphicsUpdate(_)) { graphics_updates += 1; } },
            Err(e) => { errs += 1; if errs <= 8 { println!("  frame {n} action={action} len={len}: ERR {e}"); } }
        }
    }
    // black check
    let data = image.data();
    let nonzero = data.chunks(4).filter(|p| p[0]!=0 || p[1]!=0 || p[2]!=0).count();
    let total = (width as usize)*(height as usize);
    println!("frames={n} decode_errors={errs} graphics_updates={graphics_updates} nonblack_px={nonzero}/{total} ({:.1}%)", 100.0*nonzero as f64/total as f64);
    let img: image::RgbaImage = image::ImageBuffer::from_raw(width as u32, height as u32, data.to_vec()).unwrap();
    img.save("/tmp/replay_diag.png").unwrap();
    println!("wrote /tmp/replay_diag.png");
}
