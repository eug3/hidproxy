# 如何添加自定义图标

## 方法1: 使用现有的.ico文件
1. 将您的图标文件命名为 `app.ico`
2. 放置在 `injector/launcher/` 目录下
3. 重新编译项目

## 方法2: 在线生成图标
1. 访问 https://www.icoconverter.com/ 或 https://convertico.com/
2. 上传一张图片(PNG/JPG等)
3. 转换为.ico格式
4. 下载并保存为 `app.ico`
5. 放置在 `injector/launcher/` 目录下
6. 重新编译

## 方法3: 使用Windows自带工具
1. 使用Paint创建一个图像
2. 使用在线转换工具转换为.ico
3. 保存为 `app.ico`

## 临时解决方案
如果没有图标文件,您可以:
1. 从Windows系统中复制一个图标:
   - C:\Windows\System32\*.ico
2. 或者使用任何.exe文件提取图标(使用ResourceHacker等工具)

## 推荐尺寸
- 16x16, 32x32, 48x48, 256x256 像素
- 包含多个尺寸的.ico文件效果最好
