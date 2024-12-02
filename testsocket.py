# coding: utf-8
from AesCrypto import AesCrypto
from RsaCrypto import RsaCrypto

pubkeydict = {}
aeskeydict_100 = {}
aeskeydict_101 = {}

# 运行时产生RSA操作类
rsaob1 = RsaCrypto()
rsaob2 = RsaCrypto()

# 双方在建立连接时交换RSA公钥，并存储在对应的map中
pubkeydict["198.168.0.100"] = rsaob1.Pubkey
pubkeydict["198.168.0.101"] = rsaob2.Pubkey

# 获取到公钥之后，创建AES操作类，并在连接端生成密钥
# 192.168.0.100端
aesob1 = AesCrypto()
aeskeydict_100["198.168.0.100 --- 192.168.0.101"] = aesob1.GenerateKey()
aesob1.NewAesCrypto(aeskeydict_100["198.168.0.100 --- 192.168.0.101"])

# 将密钥用RSA加密(192.168.0.100端)
crykey = rsaob1.Encrypt(aeskeydict_100["198.168.0.100 --- 192.168.0.101"], pubkeydict["198.168.0.101"])

# 192.168.0.101端
aeskeydict_101["198.168.0.100 --- 192.168.0.101"] = rsaob2.Decrypt(crykey)
aesob2 = AesCrypto()
aesob2.NewAesCrypto(aeskeydict_101["198.168.0.100 --- 192.168.0.101"])

# ======================================
# 双方之后使用AES进行通信
# ======================================
text = "该吃饭了"
crytext = aesob1.Encrypt(text)  # 产生加密数据，通过socket进行传输
dcrytext = aesob2.Decrypt(crytext)

print("加密数据为:")
print(crytext)
print("解密数据为:")
print(dcrytext)

crytext = aesob1.test_EncryptFile('./test.txt')
dcrytext = aesob2.Decrypt(crytext)

print("加密数据为:")
print(crytext)
print("解密数据为:")
print(dcrytext)



crytext = aesob1.test_EncryptImage('./index.jpg')
dcrytext = aesob2.Decrypt(crytext)

print("加密数据为:")
print(crytext)
print("解密数据为:")
print(dcrytext)