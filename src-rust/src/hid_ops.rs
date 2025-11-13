/// HID操作：SetFeature → FlushQueue → GetFeature 完整流程
/// 使用Windows原生API确保正确的操作顺序

#[cfg(target_os = "windows")]
use {
    std::ffi::c_void,
    std::os::windows::ffi::OsStrExt,
    std::ffi::OsStr,
    windows::Win32::Devices::HumanInterfaceDevice::{HidD_SetFeature, HidD_GetFeature, HidD_FlushQueue},
    windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    windows::Win32::Foundation::CloseHandle,
};

/// 为HID设备执行完整的SetFeature→FlushQueue→GetFeature操作
/// 
/// 每个73字节的操作都必须执行这个完整序列：
/// 1. SetFeature - 发送请求到设备
/// 2. FlushQueue - 清空设备缓冲区（hidapi缺失的关键步骤）
/// 3. GetFeature - 读取响应
#[cfg(target_os = "windows")]
pub fn hid_feature_report_sequence(device_path: &str, buffer: &mut [u8]) -> Result<(), String> {
    use windows::core::PCWSTR;
    
    // 将设备路径转换为Windows wide字符串
    let os_str = OsStr::new(device_path);
    let mut wide_path: Vec<u16> = os_str.encode_wide().collect();
    wide_path.push(0); // Add null terminator
    
    unsafe {
        // Open device using Windows API
        let handle = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            0, // No specific access needed for feature reports
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        ).map_err(|_| "Failed to open device".to_string())?;
        
        // 步骤1: SetFeature - 发送请求到设备
        let set_result = HidD_SetFeature(
            handle,
            buffer.as_mut_ptr() as *const c_void,
            buffer.len() as u32,
        );

        if !set_result.as_bool() {
            let _ = CloseHandle(handle);
            return Err("HidD_SetFeature failed".to_string());
        }

        // 步骤2: FlushQueue - 清空设备缓冲区
        // 这是关键步骤，hidapi中缺失了这一步
        let flush_result = HidD_FlushQueue(handle);
        if !flush_result.as_bool() {
            let _ = CloseHandle(handle);
            return Err("HidD_FlushQueue failed".to_string());
        }

        // 步骤3: GetFeature - 读取响应
        let get_result = HidD_GetFeature(
            handle,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
        );

        let _ = CloseHandle(handle);

        if !get_result.as_bool() {
            return Err("HidD_GetFeature failed".to_string());
        }

        Ok(())
    }
}
