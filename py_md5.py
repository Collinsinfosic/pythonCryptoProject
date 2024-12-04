import hashlib

#使用迭代器加载字典
def load_password(filepath):
    with open(filepath,'r') as f:
        for line in f:
            yield line
# 使用md5加密
def md5_encode(password):
    md5 = hashlib.md5()
    md5.update(password.encode('UTF-8'))
    return md5.hexdigest()


if __name__ == '__main__':
    hashcode = 'e10adc3949ba59abbe56e057f20f883e'
    file_generator  = load_password('1.txt')
    for line in file_generator:
        password = line.replace('\n','')
        pass_decode = md5_encode(password)
        if(pass_decode == hashcode):
            print('OK',password)
        else:
            print('NO')

