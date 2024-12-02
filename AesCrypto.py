# coding: utf-8
# 默认encode和decode是使用utf-8编码
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import b2a_hex, a2b_hex
import os
import base64

# 参考https://www.cnblogs.com/xiao-apple36/p/8744408.html

# =====================================================
# 使用时，可以实时的根据IP生成使用的对称密钥，并存放在本
# 地的map中，RSA公钥也可以存放在一个公共的map中
# 一个点对点通信，对应一个密钥，对应一个AesCrypto类
# =====================================================
class AesCrypto():
    def __init__(self):
        self.mode = AES.MODE_ECB
        # ===========================================
        # 定义AES密钥长度，所有长度都用字节表示
        # AES区块长度为16字节，密钥长度为16/24/32字节
        # ===========================================
        self.AES_CONTENT_LENGTH = 16
        self.AES_KEY_LENGTH = 16  # 可选择16/24/32
        self.FileIndex = 1


    def GenerateKey(self):
        return get_random_bytes(self.AES_KEY_LENGTH)  # 产生随机密钥


    def NewAesCrypto(self, key):
        self.cryptor = AES.new(key, self.mode)


    # 加密函数，如果text不是16的倍数【加密文本text的字节数必须为16的倍数！】，那就补足为16的倍数
    # 加密内容需要长达16位字符，所以进行空格拼接，一个空格是一个字节
    def pad(self, text):
        text += '1'  # 用最后一个字符来区分传输的数据类型，1为普通数据，2为文件，3为图片
        text_flag = ''
        text_flag = text
        length = len(text_flag.encode())  # 返回text的字节数
        while length % self.AES_CONTENT_LENGTH != 0:
            text += ' '
            length += 1
        return text


    def Encrypt(self, text):
        # 加密的字符需要转换为bytes
        self.ciphertext = self.cryptor.encrypt(self.pad(text).encode())
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)  # 转换为16进制


    def Decrypt(self, text):
        plain_text = self.cryptor.decrypt(a2b_hex(text)).decode()  # plain_text为字符串
        # 判断是文件还是普通数据
        plain_text_final = plain_text.rstrip(' ')  # 去除后端空格
        if plain_text_final[(len(plain_text_final)-1)] == '1':
            return plain_text_final[:(len(plain_text_final)-1)]
        elif plain_text_final[(len(plain_text_final)-1)] == '2':
            plain_text_final = plain_text_final[:(len(plain_text_final)-1)]
            buf = plain_text_final.encode()  # encode用于将str格式编码成byte格式，与decode相对
            filepath = './'+str(self.FileIndex)+'.txt'
            self.FileIndex += 1
            with open(filepath, 'wb') as f:
                f.write(buf)
            f.close()
            return filepath
        elif plain_text_final[(len(plain_text_final)-1)] == '3':
            plain_text_final = plain_text_final[:(len(plain_text_final)-1)]
            buf = plain_text_final.encode()
            # 将二进制字符串转换为图片
            filepath = './'+str(self.FileIndex)+'.png'
            self.FileIndex += 1
            with open(filepath, 'wb') as f:
                f.write(base64.b64decode(buf))
            f.close()
            return filepath

    # =============================================================
    # 目前只能加解密utf-8能够解析的编码格式，所以图片会存在一些问题
    # 希望可以通过base64实现
    # =============================================================

    def test_EncryptFile(self, filepath):
        buf = bytearray(os.path.getsize(filepath))
        with open(filepath, 'rb') as f:
            buf = f.read()  # 读取的文件byte字节存储在buf中
        f.close()
        # 对buf进行pad处理
        bufstr = buf.decode()  # decode用于将byte解码成str格式，decode只能解码asc码
        bufstr += '2'  # 用最后一个字符来区分传输的数据类型，1为普通数据，2为文件，3为图片
        length = (len(buf)+1)
        while length % self.AES_CONTENT_LENGTH != 0:
            bufstr += ' '
            length += 1
        self.ciphertext = self.cryptor.encrypt(bufstr.encode())
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)  # 转换为16进制

    def test_EncryptImage(self, filepath):
        with open(filepath, 'rb') as f:
            buf = base64.b64encode(f.read())  # 直接将图片转换为字节流
        f.close()
        # 将字节流转化为utf-8编码的字符串
        # print(buf)
        bufstr = buf.decode()
        # 对buf进行pad处理
        bufstr += '3'  # 用最后一个字符来区分传输的数据类型，1为普通数据，2为文件，3为图片
        length = (len(buf)+1)
        while length % self.AES_CONTENT_LENGTH != 0:
            bufstr += ' '
            length += 1
        self.ciphertext = self.cryptor.encrypt(bufstr.encode())
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)  # 转换为16进制






if __name__ == '__main__':
    pc = AesCrypto()  # 初始化密钥
    key = pc.GenerateKey()
    print(type(key))
    pc.NewAesCrypto(key)
    e = pc.Encrypt("你好，hello world")  # e为用16进制表示的加密数据
    pc_w = AesCrypto()
    pc_w.NewAesCrypto(key)
    print(type(e))
    d = pc_w.Decrypt(e)
    print(e, d)
