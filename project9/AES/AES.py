import numpy as np
import copy
import tool
import time
import random
plaintext = []
s="abcdefghijklmnopqrstuvwxyz"
#密钥扩展
def key_extension(key):
    global plaintext
    key_filling=[]
    for i in range(0,len(str(key))):
        key_filling.append(ord(str(key)[i]))
    x=16-len(key_filling)
    for i in range(0,x):
        key_filling.append(0)
        i+=1


    key_matrix = np.zeros((4, 44), dtype=int)
    for x in range(len(key_filling)):
        key_matrix[x % 4][x // 4] = key_filling[x]

    for i in range(4, 44):
        if i % 4 != 0:
            key_matrix[:, i] = key_matrix[:, i - 4] ^ key_matrix[:, i - 1]

        else:
            temp = np.roll(key_matrix[:, i - 1], -1)

            for j in range(len(temp)):
                row = temp[j] // 16
                col = temp[j] % 16
                temp[j] = tool.s_box[row][col]

            Rcon = [[0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00],
                    [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00],
                    [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
                    [0x1B, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]]
            temp = temp ^ Rcon[i // 4 - 1]

            key_matrix[:, i] = key_matrix[:, i - 4] ^ temp

    key_matrix=key_matrix.T
    key_matrix=key_matrix.reshape(11,4,4)
    return key_matrix


def pre_address():
    global plaintext
    global s
    length = len(s)
    remain = length%16
    if remain:s+="0"*(16-remain)
    plaintext = list(s)
    length = len(plaintext)
    for i in range(length):
        plaintext[i] = int(ord(plaintext[i]))
    for i in range(0,length,16):
            sub_plaintext = []
            for j in range(16):
                sub_plaintext.append(plaintext.pop(0))
                plaintext.append(sub_plaintext)
    for i in range(len(plaintext)):
        plaintext[i] = np.array(plaintext[i])
        plaintext[i]=np.reshape(plaintext[i],(4,4))
        plaintext[i]=plaintext[i].T

     

def initial_exchange(initial_key,group_index):
    global plaintext
    plaintext[group_index] = plaintext[group_index]^initial_key


def sub_bytes(group_index):
    global plaintext
    for i in range(4):
        for j in range(4):
            byte = hex(plaintext[group_index][i][j])[2:]
            if len(byte)==1:
                row=0
                col=int(byte[0],16)
            else:
                row = int(byte[0],16)
                col = int(byte[1],16)
            plaintext[group_index][i][j] = tool.s_box[row][col]
def shift_rows(group_index):
    global plaintext
    for i in range(4):
        if i == 1:
            for j in range(3,0,-1):
                plaintext[group_index][i][0],plaintext[group_index][i][j]= plaintext[group_index][i][j],plaintext[group_index][i][0]

        if i==2:
            plaintext[group_index][i][0],plaintext[group_index][i][2] = plaintext[group_index][i][2],plaintext[group_index][i][0]
            plaintext[group_index][i][1],plaintext[group_index][i][3] = plaintext[group_index][i][3],plaintext[group_index][i][1]
        if i==3:
            for j in range(1,4):
                plaintext[group_index][i][0],plaintext[group_index][i][j] = plaintext[group_index][i][j],plaintext[group_index][i][0]

def mod_mul(a,b):
    global plaintext
    if a==1:return b
    if a==2:
        b=bin(b)[2:]
        if len(b)<8 or b[0]=="0":
            return int(b+"0",2)

        elif b[0]=="1":
            b = b[1:]
            return int(b+"0",2)^int("00011011",2)
    elif a==3:
        return b^mod_mul(2,b)


def mix_columns(group_index):
    global plaintext
    temp = copy.deepcopy(plaintext)
    for i in range(4):
        for j in range(4):
            sum=0
            for k in range(4):
                sum = sum^(mod_mul(tool.positive_matrix[i][k],temp[group_index][k][j]))
            plaintext[group_index][i][j] = sum

def add_round_key(group_index,key,round_num):
    global plaintext
    plaintext[group_index] = plaintext[group_index]^key[round_num]

def crypto(crypto_key):
    global plaintext
    pre_address()
    k=crypto_key.encode('utf-8')

    initial_key = key_extension(k)[0]
    key = key_extension(k)[1:]
    for group_index in range(len(plaintext)):
        initial_exchange(initial_key,group_index)
        for round_num in range(9):
            sub_bytes(group_index)
            shift_rows(group_index)
            mix_columns(group_index)
            add_round_key(group_index,key,round_num)
        sub_bytes(group_index)  # 最后1轮无列混淆
        shift_rows(group_index)
        add_round_key(group_index,key,9)
    for i in range(len(plaintext)):
        plaintext[i]=plaintext[i].tolist()
        for j in range(4):
            for k in range(4):
                plaintext[i][j][k] = hex(plaintext[i][j][k])
def main():
    global plaintext
    kk="2021004600981234"
    print(f"初始明文为:",s)
    print(f"初始密钥为:{kk}")
    crypto(kk)
    print(f"经过AES加密后的密文为:{plaintext}")


if __name__=="__main__":
    main()
