# coding: utf-8
import rsa
from binascii import b2a_hex, a2b_hex

# 参考https://www.cnblogs.com/xiao-apple36/p/8744408.html

# =======================================================
# 每次新建一个RSA类时都会自动产生特有的公钥和私钥
# 私钥只允许程序内部访问，公钥为公开
# =======================================================
class RsaCrypto():
    def __init__(self):
        self.Pubkey, self.prikey = rsa.newkeys(256)

    # 用给定公钥进行加密
    def Encrypt(self, text, pubkey):
        if type(text) == bytes:
            self.ciphertext = rsa.encrypt(text, pubkey)
        elif type(text) == str:
            self.ciphertext = rsa.encrypt(text.encode(), pubkey)#加密使用字节类型数据，需要将字符串类型转换成字节类型
        # 因为rsa加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    def Decrypt(self, text):  # 固定使用自己的私钥进行解密
        decrypt_text = rsa.decrypt(a2b_hex(text), self.prikey)
        return decrypt_text


if __name__ == '__main__':
    rs_obj = RsaCrypto()  # 新建一个RSA算法类，并且自动生成公钥及私钥
    print("公钥为:",end="")
    print(rs_obj.Pubkey)
    text = '赵光耀爱吃屁'
    publickey = rsa.PublicKey(rs_obj.Pubkey.n, rs_obj.Pubkey.e)  
    #使用这种方式可以构造一个RSA公钥类，实际的n和e可以存储在map中，使用的时候再实时的构造公钥类
    #print(type(publickey.n))  # int 78位
    #print(type(publickey.e))  # int 65537
    print(len(str(publickey.n).encode()))
    print(int(str(publickey.n)))
    strpublickey = str(publickey)
    
    ency_text = rs_obj.Encrypt(text, rs_obj.Pubkey)  # test 用自己的公钥加密
    print(ency_text)
    print(rs_obj.Decrypt(ency_text).decode())  # 直接的解密结果为字节类型的字符串，需要解码一下

