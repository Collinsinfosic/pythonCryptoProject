import base64,hashlib
from Crypto.Cipher import  AES
from Crypto.Cipher import DES
from pyDes import des,CBC,ECB,PAD_PKCS5
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import Crypto.Hash.SHA256
import Crypto.Signature.PKCS1_v1_5

# 使用base64进行加解密
def base64_code(password):
    print('base64编码,原始值:',password)
    b_encode = base64.b64encode(password.encode('UTF-8'))
    print(b_encode.decode('UTF-8'))
    # print('base64解码：')
    # print(base64.b64decode(b_encode))

# 使用MD5加解密
def md5_code(password):
    print('MD5加密,原始值:', password)
    md5_encode = hashlib.md5(password.encode('UTF-8'))
    print(md5_encode.hexdigest())

# 使用AES_ECB加解密
def AES_code_ECB(password):
    BLOCK_SIZE = 16
    #加密
    key=b'1234567812345678'  #key共16位
    aes = AES.new(key,AES.MODE_ECB)#AES-ECB加密模式，并且加解密使用同一个aes对象即可
    passcode = aes.encrypt(pad(password.encode("UTF-8"),BLOCK_SIZE))
    passcode = base64.b64encode(passcode)
    print("AEC-ECB加密后:", passcode.decode('UTF-8'))
    #解密
    de_password = aes.decrypt(base64.b64decode(passcode))
    print("AEC-ECB解密后:",de_password.decode("UTF-8").replace("\x07",""))

# 使用AES_CBC加解密
def AES_CODE_CBC(password):
    #加密
    key = b'1234567812345678'
    iv = b'1234567812345678'
    BLOCK_SIZE = 16 #填充值
    aes = AES.new(key,AES.MODE_CBC,iv)
    passcode = aes.encrypt(pad(password.encode('UTF-8'),BLOCK_SIZE))
    passcode = base64.b64encode(passcode)
    print("AEC-CBC加密后:", passcode.decode('UTF-8'))
    # 解密，需要创建一个新的aes对象
    de_aes = AES.new(key,AES.MODE_CBC,iv)
    passwd = de_aes.decrypt(base64.b64decode(passcode)).decode("UTF-8")
    print("AES-CBC解密后：",passwd.replace("\x07",""))

# 使用DES_ECB加解密
def DES_CODE_ECB(password):
    # 加密
    key = b'12345678'
    des = DES.new(key,DES.MODE_ECB)
    passcode = des.encrypt(pad(password.encode("UTF-8"),8))
    passcode = base64.b64encode(passcode)
    print("DES-ECB加密后:",passcode.decode("UTF-8"))
    #解密
    password = des.decrypt(base64.b64decode(passcode)).decode("UTF-8").replace("\x07","")
    print("DES-ECB解密后:",password)

# 使用DES_CBC加解密
def DES_CODE_CBC(password):
    #加密
    key = b'12345678'
    iv= b'12345678'
    des = DES.new(key,DES.MODE_CBC,iv)
    passcode = des.encrypt(pad(password.encode("UTF-8"),8))
    passcode = base64.b64encode(passcode)
    print("DES-CBC加密后:",passcode.decode("UTF-8"))
    des_de = DES.new(key, DES.MODE_CBC, iv)
    password= des_de.decrypt(base64.b64decode(passcode)).decode("UTF-8").replace("\x07","")
    print("DES-CBC解密后:",password)

#生成公钥和私钥
def product_key():
    rsa_key = RSA.generate(1024)
    pub_key = rsa_key.publickey().export_key()
    pri_key = rsa_key.export_key()
    with open('./pub.pem','wb') as f:
        f.write(pub_key)
    with open('./pri.pem','wb') as f:
        f.write(pri_key)

#REAj加解密
def RSA_CODE(password):
    # 从文件中提取公司钥
    with open('./pub.pem','r') as f:
        pub_bytes = f.read()
    with open('./pri.pem', 'r') as f:
        pri_bytes = f.read()
    pri_key = RSA.import_key(pri_bytes)
    pub_key = pri_key.publickey()
    #私钥中包含公钥，可以从私钥里面提取，但是公钥不能提取私钥
    pub_cipher= PKCS1_v1_5.new(pub_key)

    # 加密
    #创建公钥密码器，返回类型是对象
    passcode = pub_cipher.encrypt(password.encode("UTF-8"))
    passcode = base64.b64encode(passcode)
    print("RSA公钥加密后:",passcode.decode("UTF-8"))

    #解密
    #创建私钥密码器
    pri_cipher = PKCS1_v1_5.new(pri_key)
    password = pri_cipher.decrypt(base64.b64decode(passcode),sentinel=None)
    print("RSA私钥解密后:",password.decode("UTF-8"))

#签名与验签
def  RSA_sign(password):
    data_content = password.encode("UTF-8")
    #从文件中提取公私钥
    with open('./pub.pem','r') as f:
        pub_bytes = f.read()
    with open('./pri.pem', 'r') as f:
        pri_bytes = f.read()
    pri_key = RSA.import_key(pri_bytes)
    pub_key = pri_key.publickey()

    #创建私钥签名工具
    pri_signer = Crypto.Signature.PKCS1_v1_5.new(pri_key)
    #创建HASH对象，使用SHA256
    msg_hash = Crypto.Hash.SHA256.new()
    #先对数据进行hash
    msg_hash.update(data_content)
    #对密码的hash进行签名
    singnature_result = pri_signer.sign(msg_hash)
    print("签名： ",base64.b64encode(singnature_result).decode())
    '''
    使用公钥验证签名
    '''
    #创建公钥验签工具
    pub_sginer = Crypto.Signature.PKCS1_v1_5.new(pub_key)
    verify = pub_sginer.verify(msg_hash,singnature_result)
    print("签名验证结果:",verify)

if __name__ == '__main__':
    password = 'xiaodisec'
    # base64_code(password)
    # md5_code(password)
    # print("AES加密，原始值:", password)
    '''
        AEC-ECB加密不需要提供IV偏移量,并且需要加密的对象必须是16的倍数
        所以下列代码使用BLOCK_SIZE参数，并用pcsk5padding进行补全
    '''
    # AES_code_ECB(password)
    # AES_CODE_CBC(password)
    '''
            1. DES-EBC加密不需要提供IV偏移量,并且key必须是8字节
            2. 使用BLOCK_SIZE参数，并用pcsk5padding进行补全
        '''
    # DES_CODE_ECB(password)
    # DES_CODE_CBC(password)
    '''
        1.使用product_key生成公钥，私钥
        2.将公私钥传给加密算法
    '''
    # product_key()

    # RSA_CODE(password)
    RSA_sign(password)