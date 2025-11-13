"""
HID设备卡片校验和更新工具

功能:
1. 读取扇区0获取UID
2. 读取扇区1定位校验和字段
3. 根据UID和HID生成新的校验和
4. 更新扇区1中的校验和字段

使用方法:
    python update_card_checksum.py <HID> [--year YEAR]
"""

import hashlib
import sys
from datetime import datetime


# ==================== 扇区数据结构定义 ====================

class Sector0:
    """扇区0：UID存储"""
    def __init__(self):
        self.uid = None
        self.manufacturer_data = None
    
    def parse(self, data):
        """
        解析扇区0数据
        
        Args:
            data: 扇区0的原始字节数据
        
        Returns:
            UID（10位数字字符串）
        """
        # UID通常在块0的前4字节
        # 需要根据实际卡片格式调整
        if len(data) >= 4:
            # 将字节转换为UID数字
            # 具体转换逻辑需要根据实际格式调整
            self.uid = self._extract_uid(data[:4])
        return self.uid
    
    def _extract_uid(self, uid_bytes):
        """
        从字节数据提取UID
        
        Args:
            uid_bytes: 4字节UID数据
        
        Returns:
            10位数字字符串
        """
        # 示例：将4字节转换为整数
        uid_int = int.from_bytes(uid_bytes, byteorder='little')
        return str(uid_int)


class Sector1:
    """扇区1：用户数据和校验和"""
    
    # 字段位置定义（需要根据实际卡片调整）
    CHECKSUM_BLOCK = 2      # 校验和所在块号
    CHECKSUM_OFFSET = 0     # 校验和在块内的偏移
    CHECKSUM_LENGTH = 33    # 校验和固定长度
    
    def __init__(self):
        self.raw_data = None
        self.name = None
        self.annual_check_1 = None
        self.annual_check_2 = None
        self.status = None
        self.checksum = None
        self.company = None
    
    def parse(self, data):
        """
        解析扇区1数据
        
        Args:
            data: 扇区1的原始字节数据（通常是48字节，3个块）
        
        Returns:
            当前校验和字符串
        """
        self.raw_data = data
        
        # 定位校验和字段
        checksum_start = self.CHECKSUM_BLOCK * 16 + self.CHECKSUM_OFFSET
        checksum_end = checksum_start + self.CHECKSUM_LENGTH
        
        if len(data) > checksum_end:
            checksum_bytes = data[checksum_start:checksum_end]
            try:
                self.checksum = checksum_bytes.decode('ascii').strip()
            except UnicodeDecodeError:
                self.checksum = None
        
        return self.checksum
    
    def update_checksum(self, new_checksum):
        """
        更新校验和字段
        
        Args:
            new_checksum: 新的33字符校验和
        
        Returns:
            更新后的扇区数据
        """
        if len(new_checksum) != self.CHECKSUM_LENGTH:
            raise ValueError(f"校验和长度必须是{self.CHECKSUM_LENGTH}字符")
        
        # 复制原始数据
        new_data = bytearray(self.raw_data)
        
        # 更新校验和字段
        checksum_start = self.CHECKSUM_BLOCK * 16 + self.CHECKSUM_OFFSET
        checksum_bytes = new_checksum.encode('ascii')
        
        for i, byte in enumerate(checksum_bytes):
            new_data[checksum_start + i] = byte
        
        return bytes(new_data)
    
    def display(self):
        """显示扇区1的字段信息"""
        print("\n扇区1数据:")
        print(f"  当前校验和: {self.checksum if self.checksum else '未找到'}")
        print(f"  校验和位置: 块{self.CHECKSUM_BLOCK}, 偏移{self.CHECKSUM_OFFSET}")
        print(f"  校验和长度: {self.CHECKSUM_LENGTH}字节")


# ==================== 校验和生成算法 ====================

def generate_checksum(uid, hid, year_value=None):
    """
    生成HID设备33字符校验和
    
    参数:
        uid (str or int): 用户ID，10位数字
        hid (int): 硬件设备ID，9位数字
        year_value (int, optional): 年份值，默认使用当前年份
    
    返回:
        str: 33字符校验和字符串
    """
    # 使用当前年份（未年检设备）
    if year_value is None:
        year_value = datetime.now().year
    
    # 确保UID和HID是字符串格式
    uid_str = str(uid)
    hid_str = str(hid)
    
    # 1. 构建MD5输入字符串
    input_str = f"1{uid_str}12{hid_str}{year_value}"
    
    # 2. 计算MD5哈希值
    md5_hash = hashlib.md5(input_str.encode()).hexdigest().upper()
    
    # 3. 生成最终校验和
    checksum = "0" + md5_hash
    
    return checksum


def verify_checksum(uid, hid, expected_checksum, year_value=None):
    """
    验证校验和是否正确
    
    参数:
        uid: 用户ID
        hid: 硬件设备ID
        expected_checksum: 期望的校验和
        year_value: 年份值
    
    返回:
        (bool, str): (是否匹配, 计算出的校验和)
    """
    calculated = generate_checksum(uid, hid, year_value)
    return (calculated == expected_checksum, calculated)


# ==================== 卡片操作函数 ====================

def read_sector_0():
    """
    读取扇区0数据
    
    返回:
        UID字符串
    
    注意: 这里需要实现实际的卡片读取逻辑
    """
    # TODO: 实现实际的读卡器操作
    # 示例返回
    print("读取扇区0...")
    
    # 模拟数据（需要替换为实际读卡操作）
    # example_data = b'\x73\xAC\x5E\x4B\x...'
    # sector0 = Sector0()
    # uid = sector0.parse(example_data)
    
    # 临时返回示例UID
    uid = "1264495731"
    print(f"  UID: {uid}")
    return uid


def read_sector_1():
    """
    读取扇区1数据
    
    返回:
        Sector1对象
    
    注意: 这里需要实现实际的卡片读取逻辑
    """
    print("读取扇区1...")
    
    # TODO: 实现实际的读卡器操作
    # 模拟数据（需要替换为实际读卡操作）
    # example_data = b'...(48 bytes)...'
    # sector1 = Sector1()
    # sector1.parse(example_data)
    
    # 返回模拟对象
    sector1 = Sector1()
    sector1.checksum = "02F4DE5D2F70DF1F86CA3B690BF304B44"
    return sector1


def write_sector_1(sector_data):
    """
    写入扇区1数据
    
    参数:
        sector_data: 要写入的扇区数据（48字节）
    
    注意: 这里需要实现实际的卡片写入逻辑
    """
    print("写入扇区1...")
    
    # TODO: 实现实际的写卡器操作
    print(f"  数据长度: {len(sector_data)} 字节")
    print("  写入成功!")


# ==================== 主程序 ====================

def update_card(hid, year_value=None, dry_run=False):
    """
    更新卡片校验和
    
    参数:
        hid (int): 硬件设备ID
        year_value (int, optional): 年份值
        dry_run (bool): 是否仅模拟运行（不实际写入）
    """
    print("="*80)
    print("HID设备卡片校验和更新工具")
    print("="*80)
    
    # 1. 读取扇区0获取UID
    uid = read_sector_0()
    if not uid:
        print("❌ 错误: 无法读取UID")
        return False
    
    # 2. 读取扇区1获取当前校验和
    sector1 = read_sector_1()
    old_checksum = sector1.checksum
    sector1.display()
    
    # 3. 生成新的校验和
    print(f"\n生成新校验和:")
    print(f"  UID: {uid}")
    print(f"  HID: {hid}")
    print(f"  年份: {year_value if year_value else f'{datetime.now().year} (当前年份)'}")
    
    new_checksum = generate_checksum(uid, hid, year_value)
    print(f"\n  旧校验和: {old_checksum}")
    print(f"  新校验和: {new_checksum}")
    
    if old_checksum == new_checksum:
        print("\n✅ 校验和已是最新，无需更新")
        return True
    
    # 4. 更新校验和
    if dry_run:
        print("\n⚠️  模拟运行模式，不实际写入卡片")
        return True
    
    try:
        new_sector_data = sector1.update_checksum(new_checksum)
        write_sector_1(new_sector_data)
        print("\n✅ 校验和更新成功!")
        return True
    except Exception as e:
        print(f"\n❌ 更新失败: {e}")
        return False


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='HID设备卡片校验和更新工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用当前年份更新校验和
  python update_card_checksum.py 765674391
  
  # 使用指定年份更新校验和
  python update_card_checksum.py 765674391 --year 2022
  
  # 模拟运行（不实际写入）
  python update_card_checksum.py 765674391 --dry-run
  
  # 验证现有校验和
  python update_card_checksum.py 765674391 --verify
        """
    )
    
    parser.add_argument('hid', type=int, help='硬件设备ID（9位数字）')
    parser.add_argument('--year', type=int, help='年份值（默认使用当前年份）')
    parser.add_argument('--dry-run', action='store_true', help='模拟运行，不实际写入卡片')
    parser.add_argument('--verify', action='store_true', help='仅验证现有校验和')
    
    args = parser.parse_args()
    
    if args.verify:
        # 验证模式
        uid = read_sector_0()
        sector1 = read_sector_1()
        is_valid, calculated = verify_checksum(uid, args.hid, sector1.checksum, args.year)
        
        print(f"\n校验和验证:")
        print(f"  当前: {sector1.checksum}")
        print(f"  计算: {calculated}")
        print(f"  结果: {'✅ 匹配' if is_valid else '❌ 不匹配'}")
    else:
        # 更新模式
        update_card(args.hid, args.year, args.dry_run)


if __name__ == "__main__":
    # 如果没有命令行参数，显示帮助
    if len(sys.argv) == 1:
        print(__doc__)
        print("\n使用 --help 查看详细帮助")
    else:
        main()
