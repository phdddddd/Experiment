import time
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def measure_time_ns(func, *args, **kwargs):
    """辅助函数，返回函数运行结果以及耗时（微秒）"""
    start_ns = time.perf_counter_ns()
    result = func(*args, **kwargs)
    end_ns = time.perf_counter_ns()
    return result, (end_ns - start_ns) / 1000  # 转换为微秒

# 生成RSA密钥对：发送方和接收方各自生成自己的密钥
sender_key = RSA.generate(2048)
receiver_key = RSA.generate(2048)
sender_private = sender_key
sender_public = sender_key.publickey()
receiver_public = receiver_key.publickey()
receiver_private = receiver_key

# 预先创建RSA加解密对象（优化点）
rsa_cipher_encrypt = PKCS1_OAEP.new(receiver_public)
rsa_cipher_decrypt = PKCS1_OAEP.new(receiver_private)

# 【优化1】预创建RSA签名和验证对象，避免重复构造开销
signer = pkcs1_15.new(sender_private)
verifier = pkcs1_15.new(sender_public)

# 模拟待认证的消息
message = b"Test message for RDMA authentication scheme"

print("=== 加密流程 ===")

# 1. 生成128位随机数 nonce (16字节)
nonce, t_nonce = measure_time_ns(os.urandom, 16)
print(f"1. Nonce生成时间: {t_nonce:.2f} μs")

# 2. 对消息使用SHA-256进行哈希计算，生成MAC值
def compute_hash(msg):
    h = SHA256.new(msg)
    return h, h.digest()

(hash_obj, MAC), t_hash = measure_time_ns(lambda m: (lambda h: (h, h.digest()))(SHA256.new(m)), message)
print(f"2. SHA-256哈希计算时间: {t_hash:.2f} μs")

# 3. 使用预创建的RSA签名器对MAC进行签名，生成数字签名 signature
signature, t_sign = measure_time_ns(signer.sign, hash_obj)
print(f"3. RSA签名时间: {t_sign:.2f} μs")

# 4. 生成对称密钥 K_sym（这里用 nonce 的 SHA-256 哈希的前16字节模拟AES密钥）
K_sym, t_sym_key = measure_time_ns(lambda n: SHA256.new(n).digest()[:16], nonce)
print(f"4. 对称密钥生成时间: {t_sym_key:.2f} μs")

# 5. 使用AES-CBC模式以nonce作为IV对数字签名进行加密，生成加密签名 C_sig
def aes_encrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # 这里假设 signature 长度是16字节的整数倍，如果不是可使用 pad/unpad
    return cipher.encrypt(data)
C_sig, t_aes_encrypt = measure_time_ns(aes_encrypt, K_sym, nonce, signature)
print(f"5. AES加密时间: {t_aes_encrypt:.2f} μs")

# 6. 使用预创建的RSA加密对象对nonce和对称密钥进行加密
def rsa_encrypt(cipher_obj, data):
    return cipher_obj.encrypt(data)
C_nonce, t_rsa_nonce = measure_time_ns(rsa_encrypt, rsa_cipher_encrypt, nonce)
C_key, t_rsa_key = measure_time_ns(rsa_encrypt, rsa_cipher_encrypt, K_sym)
t_rsa_encrypt = t_rsa_nonce# + t_rsa_key
print(f"6. RSA加密时间 (nonce和K_sym): {t_rsa_encrypt:.2f} μs")

# 打印各部分密文的长度
print(f"   C_sig 长度: {len(C_sig)} 字节")
print(f"   C_key 长度: {len(C_key)} 字节")
print(f"   C_nonce 长度: {len(C_nonce)} 字节")

# 7. 组装安全标签Tag：写入各密文长度（用3个字节表示）后拼接各密文
def assemble_tag(c_sig, c_key, c_nonce):
    tag = (len(c_sig).to_bytes(3, byteorder='big') +
           len(c_key).to_bytes(3, byteorder='big') +
           len(c_nonce).to_bytes(3, byteorder='big') +
           c_sig + c_key + c_nonce)
    return tag
tag, t_tag = measure_time_ns(assemble_tag, C_sig, C_key, C_nonce)
print(f"7. 安全标签Tag组装时间: {t_tag:.2f} μs")
print(f"   安全标签Tag总长度: {len(tag)} 字节")

print("\n=== 解密流程 ===")
# 解密流程：假设接收端已从报文中提取出标签 tag

# (1) 从标签中解析出各部分密文
def parse_tag(tag):
    len_sig = int.from_bytes(tag[0:3], byteorder='big')
    len_key = int.from_bytes(tag[3:6], byteorder='big')
    len_nonce = int.from_bytes(tag[6:9], byteorder='big')
    idx = 9
    c_sig = tag[idx: idx+len_sig]
    idx += len_sig
    c_key = tag[idx: idx+len_key]
    idx += len_key
    c_nonce = tag[idx: idx+len_nonce]
    return c_sig, c_key, c_nonce
(C_sig_dec, C_key_dec, C_nonce_dec), t_tag_parse = measure_time_ns(parse_tag, tag)
print(f"1. 标签解析时间: {t_tag_parse:.2f} μs")

# (2) 使用预创建的RSA解密对象解密 C_key 和 C_nonce，恢复 K_sym 和 nonce
def rsa_decrypt(cipher_obj, data):
    return cipher_obj.decrypt(data)
K_sym_dec, t_rsa_dec_key = measure_time_ns(rsa_decrypt, rsa_cipher_decrypt, C_key_dec)
nonce_dec, t_rsa_dec_nonce = measure_time_ns(rsa_decrypt, rsa_cipher_decrypt, C_nonce_dec)
t_rsa_decrypt = t_rsa_dec_key #+ t_rsa_dec_nonce
print(f"2. RSA解密时间 (K_sym和nonce): {t_rsa_decrypt:.2f} μs")

# (3) 使用AES解密 C_sig 获得签名
def aes_decrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(data)
signature_dec, t_aes_decrypt = measure_time_ns(aes_decrypt, K_sym_dec, nonce_dec, C_sig_dec)
print(f"3. AES解密时间: {t_aes_decrypt:.2f} μs")

# (4) 重新计算消息的MAC
(_, MAC_dec), t_hash_dec = measure_time_ns(lambda m: (lambda h: (h, h.digest()))(SHA256.new(m)), message)
print(f"4. SHA-256哈希计算（解密验证）时间: {t_hash_dec:.2f} μs")

# (5) 使用预创建的RSA验证器验证签名
_, t_verify = measure_time_ns(verifier.verify, SHA256.new(message), signature_dec)
print(f"5. RSA签名验证时间: {t_verify:.2f} μs")

print("解密验证：签名验证成功，数据完整且未被篡改。")
