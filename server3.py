import socket
import threading
import time
import pymysql
import sys
from decimal import Decimal
import datetime
import random
import hashlib
import traceback
from rsa import PrivateKey
import rsa
from Crypto.Cipher import AES
import hmac
import struct
import os
import ast
class operateonlinebookstore:
    def __init__(self):
        try:
            self.conn=pymysql.connect(*database)
            self.cur=self.conn.cursor()
        except Exception as e :
            raise e
    #添加记录
    def select_record(self,sql,param=None):
        try:
            self.cur.execute(sql,param)
            return self.cur
        except Exception as e:
            raise e
    def insert_record(self,sql,param=None):
        try:
            self.cur.execute(sql,param)
            self.conn.commit()
        except Exception as e:
            raise e

    def delete_record(self,sql,param=None):
        try:
            self.cur.execute(sql,param)
            self.conn.commit()
        except Exception as e:
            raise e
    def update_record(self,sql,param=None):
        try:
            self.cur.execute(sql,param)
            self.conn.commit()
        except Exception as e:
            raise e
    def __del__(self):
        self.cur.close()
        self.conn.close()


ADDR = ()
database=()
BUFSIZ = 1024
#随机数大小范围
CH_LOW=0
CH_HIGH=99999





def maketk(password,cha,chb):
    md5hash = hashlib.md5((password+str(cha)+str(chb)).encode())
    return md5hash.digest()

def handle(s):
    #公钥解密函数，输入比特流输出字符串
    def rsa_deciphering(crypto):
        with open("./privatekey", mode="r")as f:
            privkey = eval(f.read())
        message = rsa.decrypt(crypto, privkey)
        return message.decode()

    # 加密函数，输入任意对象输出比特流
    def myencryption(text):
        model = AES.MODE_ECB  # 定义模式
        aes = AES.new(tk, model)  # 创建一个aes对象，tk代表128bit密钥
        text = repr(text)  #对象转为字符串
        #长度不是128bit整数倍，用空格补齐
        while len(text.encode()) % 16 != 0:
            text = " " + text
        #字符串转为二进制bit流
        text = text.encode()
        #使用aes库中的加密函数
        en_text = aes.encrypt(text)  # 加密明文
        return en_text

    # 解密函数，输入比特流输出对象
    def mydeciphering(en_text):
        model = AES.MODE_ECB  # 定义模式
        aes = AES.new(tk, model)  # 创建一个aes对象
        text = aes.decrypt(en_text)  # 解密明文
        text = text.decode()#bit流转字符串
        #去掉填充空格
        while text[0] == ' ':
            text=text[1:]
        #将字符串恢复为Python对象
        text = ast.literal_eval(text)
        return text

    # 完整性验证函数，输入输出都是比特流
    def integrity_check(text):
        h = hmac.new(tk, text, digestmod='MD5')
        return h.digest()
    #通信函数
    def mysend(meg):
        meg = repr(meg).encode()
        head = struct.pack("i", len(meg))
        if (len(head + meg) > BUFSIZ):
            raise Exception("数据单次发送长度已超过缓冲区大小！")
        s.send(head + meg)

    def myrecv():
        head=s.recv(4)
        while 1:
            if(len(head)==4):
                break
            else:
                head+=s.recv(4-len(head))
        length = struct.unpack("i", head)[0]
        if length > BUFSIZ - 4:
            raise Exception("数据单次接收长度已超过缓冲区大小！")
        temp = s.recv(length)
        while 1:
            if len(temp) == length:
                break
            temp += s.recv(length - len(temp))
        return ast.literal_eval(temp.decode())

    # 打包函数，输入任意对象，输出bytes型认证码+bytes型加密内容，随机数约定为字符串型
    def mypack(meg, challenge):
        meg_content = myencryption(meg)
        meg_hmac = integrity_check(meg_content + challenge.encode())
        return meg_hmac + meg_content

    # 解包函数，输入字节流，判断完整性，返回解密的对象，随机数约定为字符串型
    def myunpack(meg, challenge):
        meg_hmac = meg[0:16]
        meg_content = meg[16:]
        if integrity_check(meg_content + challenge.encode()) != meg_hmac:
            raise Exception("传输中遭到黑客攻击，信息已被非法篡改！")
        return mydeciphering(meg_content)
    def exesql(paralist):
        if not isinstance(paralist,list):
            raise Exception("未得到列表类型数据！")
        op = operateonlinebookstore()
        flag=paralist[0]
        del paralist[0]
        if flag==1:
            reallist=[]
            sql = "select bno,bname,author,publisher,pdate,edition,price,sname,stel,sellingprice,sales " \
                  "from findbook LEFT OUTER JOIN order_view USING (stel,bno) where 1=1 "
            se_clause = ["and sname like %s ",
                         "and bno like %s ",
                         "and bname like %s ",
                         "and author like %s ",
                         "and publisher like %s ",
                         "and pdate between %s and %s "
                         ]
            or_clause = ["order by sales DESC", "order by sellingprice", "order by sellingprice DESC"]
            for i in range(5):
                if paralist[i]!=-1:
                    sql+=se_clause[i]
                    reallist.append('%'+paralist[i]+'%')
            if paralist[5]!=-1:
                sql+=se_clause[5]
                reallist.append(paralist[5])
                reallist.append(paralist[6])
            sql+=or_clause[paralist[7]]
            return op.select_record(sql,reallist).fetchall()
        elif flag==2:
            sql = "select* from book where bno=%s"
            return op.select_record(sql,paralist).fetchall()
        elif flag==3:
            sql = "select* from store where stel=%s"
            return op.select_record(sql,paralist).fetchall()
        elif flag==4:
            sql = "select* from sell where stel=%s and bno=%s"
            return op.select_record(sql,paralist).fetchall()
        elif flag==5:
            sql = "insert into ordersheet values(%s,%s,%s,%s,current_timestamp,%s)"
            paralist.insert(0,input_tel)
            op.insert_record(sql,paralist)
            return
        elif flag==6:
            sql = "select cname,ordersheet.ctel,sname,ordersheet.stel,bname,ordersheet.bno,qty,total,datetime " \
                  "from ordersheet,customer,store,book " \
                  "where ordersheet.ctel=customer.ctel " \
                  "and ordersheet.stel=store.stel " \
                  "and ordersheet.bno=book.bno " \
                  "and ordersheet.ctel=%s" \
                  "order by datetime DESC"
            return op.select_record(sql,[input_tel,]).fetchall()
        elif flag==7:
            sql = "select cname,ctel,id from customer where ctel=%s"
            return op.select_record(sql,[input_tel]).fetchall()
        elif flag==8:
            sql = "select password from customer where ctel=%s"
            return op.select_record(sql,[input_tel]).fetchall()
        elif flag==9:
            sql = "select* from customer where ctel=%s"
            return op.select_record(sql,paralist).fetchall()
        elif flag==10:
            sql = "update customer set ctel=%s WHERE ctel=%s"
            op.update_record(sql,[paralist[0],input_tel])
            return
        elif flag==11:
            sql = "delete from customer where ctel=%s"
            op.delete_record(sql,[input_tel])
            return
        elif flag==12:
            sql = "select bno,bname,author,publisher,pdate,edition,price,sellingprice,sales " \
                  "from findbook LEFT OUTER JOIN order_view USING (stel,bno) " \
                  "where stel=%s " \
                  "ORDER BY sales DESC"
            return op.select_record(sql,[input_tel]).fetchall()
        elif flag==13:
            sql = "select* from sell where bno=%s and stel=%s"
            return op.select_record(sql,[paralist[0],input_tel]).fetchall()
        elif flag==14:
            sql = "delete from sell where bno=%s and stel=%s"
            op.delete_record(sql,[paralist[0],input_tel])
            return
        elif flag==15:
            sql = "select* from sell where bno=%s"
            return op.select_record(sql,paralist).fetchall()
        elif flag==16:
            sql = "select* from ordersheet where bno=%s"
            return op.select_record(sql,paralist).fetchall()
        elif flag==17:
            sql = "delete from book where bno=%s"
            op.delete_record(sql,paralist)
            return
        elif flag==18:
            sql = "update sell set sellingprice=%s where stel=%s and bno=%s"
            paralist.insert(1,input_tel)
            op.update_record(sql,paralist)
            return
        elif flag==19:
            sql = "insert into book values(%s,%s,%s,%s,%s,%s,%s)"
            op.insert_record(sql,paralist)
            return
        elif flag==20:
            sql = "insert into sell values(%s,%s,%s)"
            op.insert_record(sql,[input_tel,paralist[0],paralist[1]])
            return
        elif flag==21:
            sql = "select cname,ordersheet.ctel,bname,ordersheet.bno,qty,total,datetime " \
                  "from ordersheet,customer,book " \
                  "where ordersheet.ctel=customer.ctel " \
                  "and ordersheet.bno=book.bno " \
                  "and ordersheet.stel=%s " \
                  "order by datetime DESC"
            return op.select_record(sql,[input_tel]).fetchall()

        elif flag==22:
            sql = "select shopkeeper,stel,shopkeeper_id,sname from store where stel=%s"
            return op.select_record(sql,[input_tel]).fetchall()
        elif flag==23:
            sql = "select password from store where stel=%s"
            return op.select_record(sql,[input_tel]).fetchall()
        elif flag==24:
            sql = "select* from store where stel=%s"
            return op.select_record(sql,paralist).fetchall()
        elif flag==25:
            sql = "update store set stel=%s WHERE stel=%s"
            op.update_record(sql,[paralist[0],input_tel])
            return
        elif flag==26:
            sql = "update store set password=%s WHERE stel=%s"
            op.update_record(sql,[paralist[0],input_tel])
            return
        elif flag==27:
            sql = "delete from store where stel=%s"
            op.delete_record(sql,input_tel)
            return
        elif flag==28:
            sql = "update store set sname=%s where stel=%s"
            op.update_record(sql,[paralist[0],input_tel])
            return
        elif flag==29:#后来发现改客户端密码的功能忘加了
            sql = "update customer set password=%s WHERE ctel=%s"
            op.update_record(sql,[paralist[0],input_tel])
            return
        else:
            raise Exception("非法的sql语句号！")











    # 执行一条指令
    def execmd(cmd):
        if cmd!="others":
            result = exesql(cmd)
            for item in result:
                mysend(mypack(item,""))
            mysend(mypack("fin",""))
            return
        else:
            challenge=str(random.randint(CH_LOW,CH_HIGH))#服务器生成随机数
            # 服务器发送随机数给客户端，mypack的第二个参数是空字符串，代表计算challenge的消息验证码时不需要插入随机数
            mysend(mypack(challenge,""))
            paralist=myunpack(myrecv(),challenge)#将随机数插入计算完整性验证码，得到的paralist是明文
            exesql(paralist)
            mysend(mypack("successful",challenge))
    tk=b'1'#临时会话密钥
    input_tel=""#用户手机号







    try:
        flag=myrecv()
        if flag=='1':
            input_id=myrecv()#判断是顾客登录还是店家登录
            input_tel=myrecv()#手机号，主键
            #以下用于查询用户的密码
            if input_id=="顾客":
                sql="select password from customer where ctel=%s"
            else:
                sql="select password from store where stel=%s"
            op = operateonlinebookstore()
            cur = op.select_record(sql,(input_tel,))
            cur_password = cur.fetchone()  # 注意：cur_password是元组类型
            #未查询到密码，说明用户不存在，断开连接并返回
            if cur_password==None:
                mysend("not exist")
                s.close()
                print("线程%s已结束" % threading.get_ident())
                return
            #生成随机数cha，即对客户端的挑战
            cha=random.randint(CH_LOW,CH_HIGH)
            mysend(cha)#挑战接入，五位
            #接收客户端的挑战应答
            rev_md5_cha=myrecv()
            #接收客户端发来的挑战chb
            chb = myrecv()
            #如果客户端的挑战应答与预期不符，则通不过验证，断开连接并返回
            local_md5_cha = hashlib.md5((cur_password[0]+str(cha)).encode()).digest()
            if rev_md5_cha!=local_md5_cha:
                mysend("not right")
                s.close()
                print("线程%s已结束" % threading.get_ident())
                return
            #服务器生成对客户端的挑战应答
            local_md5_chb=hashlib.md5((cur_password[0]+str(chb)).encode()).digest()
            mysend(local_md5_chb)
            print("通过鉴别")
            # 生成临时会话密钥
            tk = maketk(cur_password[0], cha, chb)
        elif flag=="2":
            result1=rsa_deciphering(myrecv())#解密客户端的密文
            #以下代码用于分离出cha和客户手机号
            cha=""
            while result1[0]!='*':
                cha+=result1[0]
                result1=result1[1:]
            ctel=ast.literal_eval(result1[1:])
            #生成sql语句查询手机号是否已被注册
            sql = "select* from customer where ctel=%s"
            op = operateonlinebookstore()
            cur = op.select_record(sql,ctel)
            result1 = cur.fetchone()  # 注意：cur_password是元组类型
            if result1==None:
                mysend(hashlib.md5(("successful"+cha).encode()).digest())
            else:
                mysend(hashlib.md5(("failed"+cha).encode()).digest())
                raise Exception("注册手机号已存在！")
            #解密客户端的密文
            result2=rsa_deciphering(myrecv())
            chb=""
            while result2[0]!='*':
                chb+=result2[0]
                result2=result2[1:]
            result2=ast.literal_eval(result2[1:])
            #执行插入
            sql = "insert into customer values (%s,%s,%s,%s)"
            op=operateonlinebookstore()
            op.insert_record(sql,result2)
            mysend(hashlib.md5(("successful"+chb).encode()).digest())
        elif flag=="3":
            result1 = rsa_deciphering(myrecv())
            cha = ""
            while result1[0] != '*':
                cha += result1[0]
                result1 = result1[1:]
            stel = ast.literal_eval(result1[1:])
            sql = "select* from store where stel=%s"
            op = operateonlinebookstore()
            cur = op.select_record(sql, stel)
            result1 = cur.fetchone()  # 注意：cur_password是元组类型
            if result1 == None:
                mysend(hashlib.md5(("successful" + cha).encode()).digest())
            else:
                mysend(hashlib.md5(("failed" + cha).encode()).digest())
                raise Exception("注册手机号已存在！")
            result2 = rsa_deciphering(myrecv())
            chb = ""
            while result2[0] != '*':
                chb += result2[0]
                result2 = result2[1:]
            result2 = ast.literal_eval(result2[1:])
            sql = "insert into store values (%s,%s,%s,%s,%s)"
            op = operateonlinebookstore()
            op.insert_record(sql, result2)
            mysend(hashlib.md5(("successful" + chb).encode()).digest())

        else:
            raise Exception("非法的服务号flag！")
    except Exception as e:
        print("操作失败,已断开连接!")
        print(traceback.format_exc())
        s.close()
        print("线程%s已结束" % threading.get_ident())
        return


    while(1):
        try:
            s.settimeout(600)
            print("等待客户端发送请求：", time.ctime())
            head = s.recv(4)
            if len(head)==0:
                print("得到客户端的终止信号！")
                break
            s.settimeout(5)
        except Exception as e:  # 此处可能报两种异常，要么是超时断开，要么是客户端关闭套接字断开
            print("连接已断开！")
            print("1\n", traceback.format_exc())
            break
        try:
            while 1:
                if len(head)==4:
                    break
                else:
                    head+=s.recv(4-len(head))
            length = struct.unpack("i", head)[0]
            if length > BUFSIZ - 4:
                raise Exception("数据单次接收长度已超过缓冲区大小！")
            cmd=s.recv(length)
            while 1:
                if len(cmd) == length:
                    break
                cmd += s.recv(length - len(cmd))
            cmd = ast.literal_eval(cmd.decode())
            cmd = myunpack(cmd, "")
            execmd(cmd)

        except ConnectionResetError:
            print("客户端已主动断开连接。")
            print("2\n", traceback.format_exc())
            break
        except socket.timeout:
            print("3\n", traceback.format_exc())
            continue
        except:
            print("4\n", traceback.format_exc())
            try:
                while 1:
                    if(len(s.recv(BUFSIZ))==0):
                        raise Exception("疑似收到close消息！")
            except Exception as e:
                continue
    s.close()
    print("线程%s已结束" % threading.get_ident())

if __name__ == '__main__':
    try:
        with open("./serverconfig","r") as file:
            ADDR=eval(file.readline())
            database=eval(file.readline())
            BUFSIZ=eval(file.readline())
            CH_LOW=eval(file.readline())
            CH_HIGH=eval(file.readline())


        tcpSerSock = socket.socket()
        tcpSerSock.bind(ADDR)
        tcpSerSock.listen(5)




        while True:
            print('waiting for connecting...')
            clientSock, addr = tcpSerSock.accept()
            print('connected from:', addr)
            clientSock.settimeout(5)
            t = threading.Thread(target=handle, args=(clientSock,))  # 子线程
            t.start()
    except Exception as e:
        print("程序运行中出现未知的严重错误，现已停止运行！\n" + traceback.format_exc())
        os.system("pause")
        sys.exit(1)



#通信函数ack版本备份
'''
#通信函数
    def mysend(meg):
        s.send(repr(meg).encode())
        if s.recv(3).decode() == 'ack':
            return
        else:
            raise Exception("未收到确认，数据传送失败！")

    def myrecv():
        string = s.recv(BUFSIZ).decode()
        if len(string) == 0:  # eval在处理空字符串时会返回EOF错误
            ans = ""
        else:
            ans = eval(string)
        s.send("ack".encode())
        return ans
'''
'''
        try:
            s.settimeout(600)
            print("等待客户端发送请求：",time.ctime())
            head = s.recv(4)
            print(head)
            s.settimeout(5)
        except Exception as e:#此处可能报三种异常，要么是超时断开，要么是客户端关闭套接字断开，还有就是退出异常
            print("连接已断开！")
            print("1\n",traceback.format_exc())
            break
        try:
            length = struct.unpack("i", head)[0]
            if length > BUFSIZ - 4:
                raise Exception("数据单次接收长度已超过缓冲区大小！")
            cmd=eval(s.recv(length).decode())
            cmd=myunpack(cmd,"")
            execmd(cmd)
               '''
#对close方法的解释： 调用后向对方主机发一个特定的可被永久接收的特殊0字节报文，对方主机调用send后此报文自动失效。