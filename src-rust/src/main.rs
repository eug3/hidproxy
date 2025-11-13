use hidapi::HidApi;
use std::collections::VecDeque;

#[cfg(target_os = "windows")]
mod hid_ops;

// ============================================================================
// Rockey2 USB DONGLE - Feature Report Protocol Implementation
// 
// User Area Structure:
// - 5 partitions (0-4), each 512 bytes
// - Each partition: 8 mini-blocks × 64 bytes = 512 bytes total
// - Total user area: 5 × 512 = 2560 bytes
//
// Feature Report Protocol (73 bytes fixed):
// - Byte[0]: Report ID (0x00)
// - Byte[1]: Error code (response) / Reserved (request)
// - Byte[2]: Command (0x81=read, 0x82=write, 0x87=genUID, 0x8B=transform)
// - Byte[3]: Block/Partition index (0-4)
// - Byte[4]: Mini-block index (0-7)
// - Byte[5-8]: UID (little-endian)
// - Byte[9-72]: Data payload (64 bytes)
//
// Reference: HID_DEBUG_ANALYSIS.md
// ============================================================================

const RY2_REPORTLEN: usize = 73;
const RY2_VID: u16 = 0x096E;
const RY2_PID: u16 = 0x0201;

// 错误代码定义
const RY2ERR_SUCCESS: i32 = 0;
const RY2ERR_NO_SUCH_DEVICE: i32 = -1;
const RY2ERR_VERIFY: i32 = -2;
const RY2ERR_WRONG_UID: i32 = -3;
const RY2ERR_WRONG_INDEX: i32 = -4;
const RY2ERR_WRITE_PROTECT: i32 = -5;
const RY2ERR_UNKNOWN_ERROR: i32 = -6;
const RY2ERR_NOT_OPENED_DEVICE: i32 = -7;
const RY2ERR_OPEN_DEVICE: i32 = -8;

struct RockeyDevice {
    vendor_id: u16,
    product_id: u16,
    serial_number: String,
    hid: u32,
    uid: u32,
    version: u16,
    path: String,
}

struct RockeyManager {
    devices: VecDeque<RockeyDevice>,
}

impl RockeyManager {
    fn new() -> Self {
        RockeyManager {
            devices: VecDeque::new(),
        }
    }

    fn find_devices(&mut self, api: &HidApi) -> i32 {
        self.devices.clear();
        let mut count = 0;

        for dev in api.device_list() {
            // 检查VID和PID
            if dev.vendor_id() != RY2_VID || dev.product_id() != RY2_PID {
                continue;
            }

            // 检查产品名称
            if let Some(product) = dev.product_string() {
                if !product.contains("USB DONGLE") {
                    continue;
                }

                // 获取序列号
                if let Some(serial) = dev.serial_number() {
                    let (_hid, uid) = parse_serial(serial);
                    let hid = hex_str_to_u32(&serial[0..8]);

                    let device = RockeyDevice {
                        vendor_id: dev.vendor_id(),
                        product_id: dev.product_id(),
                        serial_number: serial.to_string(),
                        hid,
                        uid,
                        version: dev.release_number(),
                        path: dev.path().to_string_lossy().to_string(),
                    };

                    println!(
                        "[DOG_{}] UID = 0x{:08X} HID = 0x{:08X} Ver = 0x{:04X}",
                        count, device.uid, device.hid, device.version
                    );
                    println!("[DOG_{}] Serial: {}", count, serial);

                    self.devices.push_back(device);
                    count += 1;
                }
            }
        }

        if count > 0 {
            count
        } else {
            RY2ERR_NO_SUCH_DEVICE
        }
    }

    fn open_device(&self, index: usize) -> Result<RockeyDevice, i32> {
        if index >= self.devices.len() {
            return Err(RY2ERR_NO_SUCH_DEVICE);
        }
        
        let device = self.devices.get(index).ok_or(RY2ERR_NO_SUCH_DEVICE)?;
        Ok(RockeyDevice {
            vendor_id: device.vendor_id,
            product_id: device.product_id,
            serial_number: device.serial_number.clone(),
            hid: device.hid,
            uid: device.uid,
            version: device.version,
            path: device.path.clone(),
        })
    }
}

fn parse_serial(serial: &str) -> (u32, u32) {
    // Serial number format: first 8 chars are HID, last 8 chars contain UID
    // Example: 2DA3439766FDEFE4
    //   HID: 2DA34397 (hex string)
    //   UID calculation: 66FDEFE4 XOR (HID bytes reversed)
    //   HID little-endian: 2DA34397 → byte reverse → 0x2DA34397 → 0x9743A32D
    //   UID = 0x66FDEFE4 XOR 0x9743A32D = 0x4B5EAC73
    
    let hid_str = if serial.len() >= 8 {
        &serial[0..8]
    } else {
        "0"
    };

    let uid_part_str = if serial.len() >= 16 {
        &serial[8..16]
    } else {
        "0"
    };

    let hid_value = hex_str_to_u32(hid_str);
    let uid_part = hex_str_to_u32(uid_part_str);

    // HID bytes need to be reversed (manually swap bytes)
    // Example: 0x2DA34397 → bytes [2D A3 43 97] → reverse → [97 43 A3 2D] → 0x9743A32D
    let bytes = hid_value.to_ne_bytes();
    let hid_reversed = ((bytes[3] as u32) << 24) 
                     | ((bytes[2] as u32) << 16)
                     | ((bytes[1] as u32) << 8)
                     | (bytes[0] as u32);

    // UID = uid_part XOR hid_reversed
    let uid = uid_part ^ hid_reversed;

    (hid_value, uid)
}

fn hex_str_to_u32(s: &str) -> u32 {
    let mut result = 0u32;
    for ch in s.chars() {
        result = result * 16
            + match ch {
                '0'..='9' => ch as u32 - '0' as u32,
                'a'..='f' => ch as u32 - 'a' as u32 + 10,
                'A'..='F' => ch as u32 - 'A' as u32 + 10,
                _ => 0,
            };
    }
    result
}

fn verify_serial_number(serial: &str, hid: u32, uid: u32) {
    // Verify that serial number is correctly calculated from HID and UID
    // Serial format: [HID as hex string (8 chars)] + [HID XOR UID as hex string (8 chars)]
    
    if serial.len() < 16 {
        eprintln!("[VERIFY] Serial too short: {}", serial);
        return;
    }
    
    // Extract and verify HID part
    let hid_part = &serial[0..8];
    let hid_calculated = hex_str_to_u32(hid_part);
    
    if hid_calculated != hid {
        eprintln!("[VERIFY] HID mismatch: serial={} calculated=0x{:08X}", hid_part, hid_calculated);
    } else {
        println!("[VERIFY] HID correct: {} = 0x{:08X}", hid_part, hid);
    }
    
    // Extract and verify UID part (second 8 chars)
    let uid_part = &serial[8..16];
    let uid_part_value = hex_str_to_u32(uid_part);
    
    // Reconstruct: uid_part should equal (HID XOR UID) converted to hex string
    let hid_bytes = hid.to_ne_bytes();
    let hid_reversed = ((hid_bytes[3] as u32) << 24) 
                     | ((hid_bytes[2] as u32) << 16)
                     | ((hid_bytes[1] as u32) << 8)
                     | (hid_bytes[0] as u32);
    
    let expected_uid_part = hid_reversed ^ uid;
    
    if uid_part_value == expected_uid_part {
        println!("[VERIFY] UID part correct: {} = 0x{:08X} (HID_reversed XOR UID)", 
                 uid_part, expected_uid_part);
    } else {
        eprintln!("[VERIFY] UID part mismatch: serial={} = 0x{:08X}, expected=0x{:08X}", 
                  uid_part, uid_part_value, expected_uid_part);
    }
    
    println!("[VERIFY] Summary: Serial should be reconstituted from HID=0x{:08X} and UID=0x{:08X}", hid, uid);
}

fn convert_err_code(code: u8) -> i32 {
    match code {
        0 => RY2ERR_SUCCESS,
        1 => RY2ERR_VERIFY,
        2 => RY2ERR_WRONG_UID,
        4 => RY2ERR_WRONG_INDEX,
        8 => RY2ERR_WRITE_PROTECT,
        _ => RY2ERR_UNKNOWN_ERROR,
    }
}

fn print_hex(data: &[u8]) {
    println!("\nData ({} bytes):", data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:04X}: ", i * 16);
        for b in chunk {
            print!("{:02X} ", b);
        }
        println!();
    }
}

fn print_binary_info(hid: u32, uid: u32) {
    // Print HID and UID in various formats
    println!("\n=== Binary Information ===");
    
    println!("HID = 0x{:08X}", hid);
    println!("  Binary: {:032b}", hid);
    println!("  Bytes (big-endian): {:02X} {:02X} {:02X} {:02X}", 
             (hid >> 24) & 0xFF,
             (hid >> 16) & 0xFF,
             (hid >> 8) & 0xFF,
             hid & 0xFF);
    let hid_bytes = hid.to_le_bytes();
    println!("  Bytes (little-endian in memory): {:02X} {:02X} {:02X} {:02X}",
             hid_bytes[0], hid_bytes[1], hid_bytes[2], hid_bytes[3]);
    
    println!("\nUID = 0x{:08X}", uid);
    println!("  Binary: {:032b}", uid);
    println!("  Bytes (big-endian): {:02X} {:02X} {:02X} {:02X}",
             (uid >> 24) & 0xFF,
             (uid >> 16) & 0xFF,
             (uid >> 8) & 0xFF,
             uid & 0xFF);
    let uid_bytes = uid.to_le_bytes();
    println!("  Bytes (little-endian in memory): {:02X} {:02X} {:02X} {:02X}",
             uid_bytes[0], uid_bytes[1], uid_bytes[2], uid_bytes[3]);
    
    // Show what gets sent to device (little-endian)
    println!("\n=== Data sent to device (bytes 5-8 in Feature Report) ===");
    println!("UID in little-endian byte order: {:02X} {:02X} {:02X} {:02X}",
             uid_bytes[0], uid_bytes[1], uid_bytes[2], uid_bytes[3]);
}

fn ry2_read(device: &RockeyDevice, block_index: u8) -> Result<Vec<u8>, i32> {
    // ========================================================================
    // Feature Report Read Operation (0x81 command)
    // 
    // Verified from actual HidD_SetFeature/HidD_GetFeature debug data:
    // 
    // SetFeature Request (73 bytes):
    //   [00 00 81 NN MM 4B 5E AC 73 | 00 00 00 ... 00]
    //    └──┬──┘ └┘ └┘ └┘ └──────────┘   └───────────────┘
    //      ID  Res Cmd Part Mini UID(little-endian)  Data area(64B)
    //
    // GetFeature Response (73 bytes):
    //   [00 EC 81 NN MM 4B 5E AC 73 | 31 32 33 34 ... ]
    //    └──┬──┘ └┘ └┘ └┘ └──────────┘   └────────────┘
    //      ID  Err Cmd Part Mini UID(echo)     Returned data(64B)
    //
    // Data layout: 5 partitions × 8 mini-blocks × 64 bytes = 2560 bytes total
    // ========================================================================
    #[cfg(not(target_os = "windows"))]
    let api = HidApi::new().map_err(|_| RY2ERR_OPEN_DEVICE)?;
    #[cfg(not(target_os = "windows"))]
    let handle = api
        .open(device.vendor_id, device.product_id)
        .map_err(|_| RY2ERR_OPEN_DEVICE)?;

    let mut block_data = Vec::new();

    // 读取8个mini-block，每个64字节
    for mini_block in 0..8 {
        let mut in_buffer = vec![0u8; RY2_REPORTLEN];
        let mut out_buffer = vec![0u8; RY2_REPORTLEN];

        // 构造Feature Report请求
        in_buffer[1] = 0;                           // 错误位置
        in_buffer[2] = 0x81;                        // 读命令
        in_buffer[3] = block_index;                 // 分区号
        in_buffer[4] = mini_block;                  // mini-block号
        in_buffer[5..9].copy_from_slice(&device.uid.to_le_bytes()); // UID (小端字节序) 
        // 打印详细的请求信息
        if mini_block == 0 { // 只在第一个mini-block打印一次完整信息
            println!("\n[REQUEST] Command 0x81 (Read)");
            println!("  Byte[0] (Report ID): 0x{:02X}", in_buffer[0]);
            println!("  Byte[1] (Reserved): 0x{:02X}", in_buffer[1]);
            println!("  Byte[2] (Command): 0x{:02X} (0x81 = Read)", in_buffer[2]);
            println!("  Byte[3] (Mini-block): 0x{:02X} ({})", in_buffer[3], in_buffer[3]);
            println!("  Byte[4] (Partition): 0x{:02X} ({})", in_buffer[4], in_buffer[4]);
            println!("  Byte[5-8] (UID): {:02X} {:02X} {:02X} {:02X} = 0x{:08X}",
                     in_buffer[5], in_buffer[6], in_buffer[7], in_buffer[8], device.uid);
        } else {
            println!("[REQUEST] Mini-block {}: Byte[3]=0x{:02X}", mini_block, in_buffer[3]);
        }

        // 发送Feature Report并接收响应
        // 使用Windows原生API确保完整的SetFeature→FlushQueue→GetFeature流程
        out_buffer.copy_from_slice(&in_buffer);
        
        // 调试：保存请求到文件
        if mini_block == 0 {
            let req_hex = in_buffer.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
            println!("[DEBUG] Request (hex): {}", req_hex);
        }
        
        // 调用Windows原生HID API执行完整的设置→刷新→获取流程
        #[cfg(target_os = "windows")]
        {
            if let Err(e) = hid_ops::hid_feature_report_sequence(&device.path, &mut out_buffer) {
                eprintln!("Failed to execute feature report: {}", e);
                return Err(RY2ERR_OPEN_DEVICE);
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // Fallback for non-Windows
            match handle.get_feature_report(&mut out_buffer) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("Failed to get feature report: {}", e);
                    return Err(RY2ERR_OPEN_DEVICE);
                }
            }
        }
        
        // 调试：保存响应
        if mini_block == 0 {
            let resp_hex = out_buffer.iter().take(20).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
            println!("[DEBUG] Response (first 20 bytes): {}", resp_hex);
        }
        
        // 检查错误码
        let err_code = convert_err_code(out_buffer[1]);
        
        if mini_block == 0 {
            println!("[RESPONSE] Status:");
        }
        println!("  Mini-block {}: Byte[1] (Error)=0x{:02X} ({})", 
                 mini_block, out_buffer[1], if err_code == 0 { "OK" } else { "ERROR" });
        
        if err_code != RY2ERR_SUCCESS {
            eprintln!("[ERROR] Read failed with code: {}", err_code);
            return Err(err_code);
        }

        // 检查命令回显
        if in_buffer[2] != out_buffer[2] {
            eprintln!("[ERROR] Command echo mismatch: sent=0x{:02X}, got=0x{:02X}", 
                      in_buffer[2], out_buffer[2]);
            return Err(RY2ERR_UNKNOWN_ERROR);
        }

        // 提取64字节有效数据
        let data_chunk = &out_buffer[9..73];
        block_data.extend_from_slice(data_chunk);
        
        // 调试输出: 显示本次读取的数据 (16进制显示)
        if mini_block < 2 || mini_block >= 6 { // 只显示第一个和最后两个mini-block
            println!("  Mini-block {} Data (hex):", mini_block);
            for (i, chunk) in data_chunk.chunks(16).enumerate() {
                let hex_str = chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                println!("    {:04X}: {}", i * 16, hex_str);
            }
        }
    }

    // 显示所有读取的数据 (16进制格式)
    println!("\n[COMPLETE DATA] 512 bytes read from partition (hex):");
    for (i, chunk) in block_data.chunks(16).enumerate() {
        let hex_str = chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
        println!("  {:04X}: {}", i * 16, hex_str);
    }

    Ok(block_data)
}

fn ry2_write(device: &RockeyDevice, block_index: u8, data: &[u8]) -> Result<(), i32> {
    // Write 512 bytes to specified partition (0-4)
    // 
    // Write operation structure (0x82 command):
    //   Byte[0]: 0x00 (Report ID)
    //   Byte[1]: 0x00 (Reserved)
    //   Byte[2]: 0x82 (Write command)
    //   Byte[3]: block_index (Partition index 0-4)
    //   Byte[4]: mini_block (Mini-block index 0-7)
    //   Byte[5-8]: UID (little-endian)
    //   Byte[9-72]: 64-byte data to write
    //
    // Response:
    //   Byte[1]: Error code (0x00 = success)
    // ========================================================================
    
    if data.len() != 512 {
        return Err(RY2ERR_WRONG_INDEX); // Data size error
    }

    let api = HidApi::new().map_err(|_| RY2ERR_OPEN_DEVICE)?;
    let handle = api
        .open(device.vendor_id, device.product_id)
        .map_err(|_| RY2ERR_OPEN_DEVICE)?;

    // Write 8 mini-blocks, 64 bytes each
    for mini_block in 0..8 {
        let mut in_buffer = vec![0u8; RY2_REPORTLEN];
        let mut out_buffer = vec![0u8; RY2_REPORTLEN];

        // Construct Feature Report request
        in_buffer[1] = 0;                           // Reserved
        in_buffer[2] = 0x82;                        // Write command
        in_buffer[3] = block_index;                 // Partition index
        in_buffer[4] = mini_block;                  // Mini-block index
        in_buffer[5..9].copy_from_slice(&device.uid.to_le_bytes()); // UID (little-endian)
        
        // Copy 64 bytes data
        let start = (mini_block as usize) * 64;
        let end = start + 64;
        in_buffer[9..73].copy_from_slice(&data[start..end]);

        // 发送Feature Report并接收响应
        match handle.get_feature_report(&mut out_buffer) {
            Ok(_) => {
                // 检查错误码
                let err_code = convert_err_code(out_buffer[1]);
                if err_code != RY2ERR_SUCCESS {
                    return Err(err_code);
                }

                // 检查命令回显
                if in_buffer[2] != out_buffer[2] {
                    return Err(RY2ERR_UNKNOWN_ERROR);
                }
            }
            Err(e) => {
                eprintln!("Failed to get feature report: {}", e);
                return Err(RY2ERR_OPEN_DEVICE);
            }
        }
    }

    Ok(())
}

fn ry2_gen_uid(device: &RockeyDevice, seed: &[u8]) -> Result<u32, i32> {
    // Generate new UID from seed (0x87 command)
    // 
    // GenUID operation structure:
    //   Byte[0]: 0x00 (Report ID)
    //   Byte[1]: 0x00 (Reserved)
    //   Byte[2]: 0x87 (GenUID command)
    //   Byte[3]: 0xFF (ARG1 parameter)
    //   Byte[4]: 0xFF (ARG2 parameter)
    //   Byte[5-8]: UID (little-endian)
    //   Byte[9-72]: Seed data (up to 64 bytes)
    //
    // Response:
    //   Byte[1]: Error code (0x00 = success)
    //   Byte[9-12]: New UID generated (little-endian)
    // ========================================================================
    
    if seed.len() > 64 {
        return Err(RY2ERR_WRONG_INDEX); // Seed too long
    }

    let api = HidApi::new().map_err(|_| RY2ERR_OPEN_DEVICE)?;
    let handle = api
        .open(device.vendor_id, device.product_id)
        .map_err(|_| RY2ERR_OPEN_DEVICE)?;

    let mut in_buffer = vec![0u8; RY2_REPORTLEN];
    let mut out_buffer = vec![0u8; RY2_REPORTLEN];

    // Construct Feature Report request
    in_buffer[1] = 0;                           // Reserved
    in_buffer[2] = 0x87;                        // GenUID command
    in_buffer[3] = 0xFF;                        // ARG1 (PAG parameter)
    in_buffer[4] = 0xFF;                        // ARG2 (PAG parameter)
    in_buffer[5..9].copy_from_slice(&device.uid.to_le_bytes()); // UID (little-endian)
    
    // Copy seed data to buffer
    in_buffer[9..9+seed.len()].copy_from_slice(seed);

    // Send Feature Report and receive response
    match handle.get_feature_report(&mut out_buffer) {
        Ok(_) => {
            // Check error code
            let err_code = convert_err_code(out_buffer[1]);
            if err_code != RY2ERR_SUCCESS {
                return Err(err_code);
            }

            // Check command echo
            if in_buffer[2] != out_buffer[2] {
                return Err(RY2ERR_UNKNOWN_ERROR);
            }

            // Extract new UID from response (bytes 9-12, little-endian)
            let new_uid_bytes = [
                out_buffer[9],
                out_buffer[10],
                out_buffer[11],
                out_buffer[12],
            ];
            let new_uid = u32::from_le_bytes(new_uid_bytes);
            Ok(new_uid)
        }
        Err(e) => {
            eprintln!("Failed to get feature report: {}", e);
            Err(RY2ERR_OPEN_DEVICE)
        }
    }
}

fn ry2_transform(device: &RockeyDevice, input_data: &[u8]) -> Result<Vec<u8>, i32> {
    // Data transformation operation (0x8B command)
    // 
    // Transform operation structure:
    //   Byte[0]: 0x00 (Report ID)
    //   Byte[1]: 0x00 (Reserved)
    //   Byte[2]: 0x8B (Transform command)
    //   Byte[3]: 0x00 (ARG1)
    //   Byte[4]: Data length (number of input bytes, max 32)
    //   Byte[5-8]: UID (little-endian)
    //   Byte[9-40]: Input data (up to 32 bytes)
    //
    // Response:
    //   Byte[1]: Error code (0x00 = success)
    //   Byte[4]: Output data length
    //   Byte[9-40]: Transformed data (up to 32 bytes)
    // ========================================================================
    
    if input_data.len() > 32 {
        return Err(RY2ERR_WRONG_INDEX); // Input data too long (max 32 bytes)
    }

    let api = HidApi::new().map_err(|_| RY2ERR_OPEN_DEVICE)?;
    let handle = api
        .open(device.vendor_id, device.product_id)
        .map_err(|_| RY2ERR_OPEN_DEVICE)?;

    let mut in_buffer = vec![0u8; RY2_REPORTLEN];
    let mut out_buffer = vec![0u8; RY2_REPORTLEN];

    // Construct Feature Report request
    in_buffer[1] = 0;                           // Reserved
    in_buffer[2] = 0x8B;                        // Transform command
    in_buffer[3] = 0x00;                        // ARG1
    in_buffer[4] = input_data.len() as u8;      // ARG2 (data length)
    in_buffer[5..9].copy_from_slice(&device.uid.to_le_bytes()); // UID (little-endian)
    
    // Copy input data
    in_buffer[9..9+input_data.len()].copy_from_slice(input_data);

    // Send Feature Report and receive response
    match handle.get_feature_report(&mut out_buffer) {
        Ok(_) => {
            // Check error code
            let err_code = convert_err_code(out_buffer[1]);
            if err_code != RY2ERR_SUCCESS {
                return Err(err_code);
            }

            // Check command echo
            if in_buffer[2] != out_buffer[2] {
                return Err(RY2ERR_UNKNOWN_ERROR);
            }

            // Extract transformed data from response (max 32 bytes)
            // Length is determined by device response at byte[4]
            let result_len = out_buffer[4] as usize;
            if result_len > 32 {
                return Err(RY2ERR_UNKNOWN_ERROR);
            }
            
            let result = out_buffer[9..9+result_len].to_vec();
            Ok(result)
        }
        Err(e) => {
            eprintln!("Failed to get feature report: {}", e);
            Err(RY2ERR_OPEN_DEVICE)
        }
    }
}

fn main() {
    println!("=== Rockey2 USB DONGLE Reader (Rust) ===\n");

    let api = match HidApi::new() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to initialize HID API: {}", e);
            return;
        }
    };

    // Find device
    let mut manager = RockeyManager::new();
    let find_result = manager.find_devices(&api);

    if find_result <= 0 {
        println!("No USB DONGLE device found");
        return;
    }

    let device_count = find_result as usize;
    println!("\n[OK] Found {} device(s)\n", device_count);

    // Open first device
    match manager.open_device(0) {
        Ok(device) => {
            println!("[OK] Device opened successfully");
            println!("  Device UID: 0x{:08X} ({})", device.uid, device.uid);
            println!("  HID: 0x{:08X}", device.hid);
            println!("  Version: 0x{:04X}", device.version);
            
            // Use device's built-in UID (auto-calculated from HID)
            println!("\n=== Auto-calculated UID from HID ===");
            println!("UID: 0x{:08X} ({})", device.uid, device.uid);

            // Verify serial number calculation
            println!("\n=== Serial Number Verification ===");
            verify_serial_number(&device.serial_number, device.hid, device.uid);
            
            // Print binary information
            print_binary_info(device.hid, device.uid);

            // ============ Demo 1: Read Data (RY2_Read - 0x81) ============
            println!("\n=== Demo 1: RY2_Read (Command 0x81) - Read all partitions (0-4) ===");
            println!("User Area: 5 partitions (0-4), each 512 bytes");
            println!("Reading method: 8 mini-blocks × 64 bytes per partition");
            println!("Using UID: 0x{:08X}", device.uid);
            
            let mut all_data = Vec::new();

            // Read all 5 partitions
            for partition_idx in 0..5 {
                println!("\n--- Reading partition {} (using UID 0x{:08X}) ---", partition_idx, device.uid);

                match ry2_read(&device, partition_idx as u8) {
                    Ok(data) => {
                        println!("[OK] Successfully read {} bytes", data.len());
                        
                        // Try to parse as ASCII
                        if let Ok(text) = std::str::from_utf8(&data[0..data.len().min(64)]) {
                            if text.chars().all(|c| c.is_ascii_graphic() || c.is_whitespace()) {
                                println!("Parseable as ASCII: {}", text.trim_end_matches('\0'));
                            }
                        }
                        
                        // Display hex dump
                        print_hex(&data);
                        all_data.extend(data);
                    }
                    Err(code) => {
                        eprintln!("[ERROR] Failed to read partition {}: error code {:?}", partition_idx, code);
                    }
                }
            }

            println!("\n=== Data Summary ===");
            println!("[OK] Total read {} bytes (expected 2560)", all_data.len());

            // ============ Demo 2: Transform Command (RY2_Transform - 0x8B) ============
            println!("\n=== Demo 2: RY2_Transform (Command 0x8B) - Data transformation ===");
            let test_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
            match ry2_transform(&device, &test_data) {
                Ok(result) => {
                    println!("[OK] Data transformation successful (input: {} bytes, output: {} bytes)", 
                             test_data.len(), result.len());
                    print!("Input:  ");
                    for b in &test_data { print!("{:02X} ", b); }
                    println!();
                    print!("Output: ");
                    for b in &result { print!("{:02X} ", b); }
                    println!();
                }
                Err(code) => {
                    eprintln!("[ERROR] Data transformation failed: error code {:?}", code);
                }
            }

            // ============ Demo 3: Generate UID (RY2_GenUID - 0x87) ============
            println!("\n=== Demo 3: RY2_GenUID (Command 0x87) - Generate new UID ===");
            let seed = b"TestSeed1234567890";
            match ry2_gen_uid(&device, seed) {
                Ok(new_uid) => {
                    println!("[OK] New UID generated successfully");
                    println!("  Original UID: 0x{:08X}", device.uid);
                    println!("  New UID:      0x{:08X}", new_uid);
                    println!("  Seed:         {:?}", std::str::from_utf8(seed).unwrap_or("<non-utf8>"));
                }
                Err(code) => {
                    eprintln!("[ERROR] UID generation failed: error code {:?}", code);
                }
            }

            // ============ Demo 4: Write Data (RY2_Write - 0x82) ============
            println!("\n=== Demo 4: RY2_Write (Command 0x82) - Write partition data ===");
            println!("⚠️  Write demo is disabled to prevent accidental device modification");
            println!("To enable, modify the Demo 4 section in the source code");
            
            // Demo code (disabled):
            // let mut write_data = vec![0u8; 512];
            // write_data[0..10].copy_from_slice(b"TestData!!");
            // match ry2_write(&device, 3, &write_data) {
            //     Ok(_) => {
            //         println!("✓ Partition 3 write successful");
            //     }
            //     Err(code) => {
            //         eprintln!("✗ Partition 3 write failed: error code {:?}", code);
            //     }
            // }

            println!("\n=== Demo completed ===");
        }
        Err(code) => {
            eprintln!("[ERROR] Cannot open device: error code {:?}", code);
        }
    }
}
