import bcrypt

# 加载字典
def load_password(filepath):
    with open(filepath,'r') as f:
        for line in f:
            yield line

def bcrypt_encode(password):
    salt = bcrypt.gensalt()#cost,默认=12
    hashed = bcrypt.hashpw(password,salt)
    return hashed

if __name__ == '__main__':
    hashcode = b'$2y$10$KA.7VYVheqod8F3X65tWjO3ZXfozNA2fC4oIZoDSu/TbfgKmiw7xO'
    for line in load_password('1.txt'):
        password = line.replace('\n','').encode('utf-8')
        hashed = bcrypt_encode(password)
        if(bcrypt.checkpw(password,hashcode)):
            print('OK',hashed)
        else:
            print('NO')

