import os
import requests

def xor_cipher(data):
    """自定义异或加密/解密函数"""
    return bytes([b ^ 0xAA for b in data])

def encode_filename(filename):
    """编码文件名（保留扩展名）"""
    # 分离文件名和扩展名
    base_name, ext = os.path.splitext(filename)
    if not base_name:
        base_name = filename  # 处理无扩展名的情况
    
    # 编码文件名部分
    encoded = bytes([ord(c) ^ 0xAA for c in base_name])
    # 组合新的文件名
    return encoded.hex() + ext

def upload_file(file_path, server_url):
    """上传文件到服务器"""
    try:
        # 编码文件名
        encoded_name = encode_filename(os.path.basename(file_path))
        
        # 读取并编码文件内容
        with open(file_path, 'rb') as f:
            original_content = f.read()
            encoded_content = xor_cipher(original_content)
        
        # 准备上传文件
        files = {
            'image': (encoded_name, encoded_content)
        }
        
        # 发送POST请求
        response = requests.post(server_url, files=files)
        
        # 返回服务器响应
        return response.text
    
    except Exception as e:
        return f"Upload failed: {str(e)}"

# 使用示例
if __name__ == "__main__":
    # 配置参数
    SERVER_URL = "http://192.168.31.210:888/sec_upload.php"  # 替换为实际服务器地址
    FILE_TO_UPLOAD = "sorted_wp-file-upload.txt"  # 要上传的文件路径
    
    # 执行上传
    result = upload_file(FILE_TO_UPLOAD, SERVER_URL)
    print("Upload Result:", result)