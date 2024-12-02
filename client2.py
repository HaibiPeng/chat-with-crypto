# coding: utf-8
# ==========================================
# 全双工点对点TCP加密通信，加密算法为RSA+AES
# ==========================================
import socket  # Python3中传输的数据是byte流
import threading

from AesCrypto import AesCrypto
from RsaCrypto import RsaCrypto
import rsa

class Client():
    def __init__(self, listenip, listenport):
        # 存储IP:RSA公钥对
        self.pubkeydict = {}
        # 存储IP:AES密钥对
        self.aeskeydict = {}
        # 运行时产生RSA操作类
        self.rsaop = RsaCrypto()
        self.listenip = listenip   # 点分十进制字符串
        self.listenport = listenport  # 整型
        self.flag = 0  # 判断是否为第一次连接，此时是否有AES密钥
    def run(self):
        # 创建两个子线程
        th_send = threading.Thread(target=self.send_thread, daemon=True)
        th_recv = threading.Thread(target=self.recv_thread, daemon=True)
        th_send.start()
        th_recv.start()
        print("主线程开启")
        # 主线程，维护程序的循环监听，没有处理
        while True:
            pass

    # ============================================
    # 输出语句只能出现在send线程中，因为在recv线程
    # 中输入会影响send线程的循环input，我们要实现的
    # 是点对点通信，而不是单纯的客户端服务器端
    # ============================================
    def recv_thread(self):
        s = socket.socket()
        s.bind((self.listenip, self.listenport))
        s.listen(5)
        c, addr = s.accept()  # 建立客户端连接，返回操作对象和客户端IP端口元组
        # print(addr)
        while True:
            if self.flag == 0:  # 说明还没有交换密钥
                # 发送公钥
                c.send((str(self.rsaop.Pubkey.n) + '#' + str(self.rsaop.Pubkey.e)).encode())
                keystr = c.recv(1024)
                # 密钥提取
                keyls = keystr.decode().split('#')
                self.pubkeydict[addr] = rsa.PublicKey(int(keyls[0]), int(keyls[1]))
                # 发送AES对称密钥
                self.aesop = AesCrypto()
                self.aeskeydict[addr] = self.aesop.GenerateKey()
                aeskeytext = self.rsaop.Encrypt(self.aeskeydict[addr], self.pubkeydict[addr])
                c.send(aeskeytext)
                # 产生AES操作机
                self.aesop.NewAesCrypto(self.aeskeydict[addr])
                # print("密钥交换及产生完成")
                self.flag = 1
            # 开启循环监听
            text_s = c.recv(1024)
            text = self.aesop.Decrypt(text_s)
            print(addr[0] + ":" + str(addr[1]) + "#", end='')
            print(text)

    def send_thread(self):
        s = socket.socket()
        conip = input("输入要连接的IP:")
        conport = input("输入要连接的端口号:")
        conport = int(conport)
        s.connect((conip, conport))
        print("连接成功")
        if self.flag == 0:  # 说明还没有进行密钥交换
            print("开始交换RSA公钥")
            keystr = s.recv(1024)  # 接收对方RSA公钥
            s.send((str(self.rsaop.Pubkey.n) + '#' + str(self.rsaop.Pubkey.e)).encode())  # 发送自己的公钥
            # 密钥提取
            keyls = keystr.decode().split('#')
            self.pubkeydict[conip] = rsa.PublicKey(int(keyls[0]), int(keyls[1]))
            print("RSA公钥交换完成，等待接收服务器加密AES密钥")
            # 接收AES密钥
            aeskey_s = s.recv(1024)
            self.aeskeydict[conip] = self.rsaop.Decrypt(aeskey_s)
            print("AES密钥接收完成")
            # 产生AES操作机
            self.aesop = AesCrypto()
            self.aesop.NewAesCrypto(self.aeskeydict[conip])
            print("密钥交换及产生完成")
            self.flag = 1
        print("可发送数据")
        # 开启循环监听
        while True:
            text = input()
            text_s = self.aesop.Encrypt(text)
            s.send(text_s)
            print("发送成功")

if __name__ == "__main__":
    client = Client("127.0.0.1", 60001)
    client.run()
