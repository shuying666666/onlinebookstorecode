# 导入第三方库
import wx
import wx.grid
import sys
import datetime
import locale
import socket
import hashlib
import random
import traceback
from rsa import PublicKey
import rsa
from Crypto.Cipher import AES
import hmac
from decimal import Decimal
import struct
import ast
import json
ADDR = ()
BUFSIZ = 1024
#随机数大小范围
CH_LOW=0
CH_HIGH=99999

clientSocket = socket.socket()  # 用户端的通信套接字，设为全局变量
tk=b'1' #临时会话密钥，初始化为1,经过密钥生成函数后是128位比特流




def maketk(password,cha,chb):
    md5hash = hashlib.md5((password+str(cha)+str(chb)).encode())
    return md5hash.digest()
#公钥加密函数，输入字符串输出比特流，最长245个字符
def rsa_encryption(object):
    object=object.encode()
    with open("./publickey", mode="r")as f:
        pubkey = eval(f.read())
    crypto = rsa.encrypt(object, pubkey)
    return crypto

#加密函数，输入任意对象输出比特流
def myencryption(text):
    model = AES.MODE_ECB  # 定义模式
    aes = AES.new(tk, model)  # 创建一个aes对象
    text=repr(text)
    while len(text.encode()) % 16 != 0:
        text = " " + text
    text=text.encode()
    en_text = aes.encrypt(text)  # 加密明文
    return en_text
#解密函数，输入比特流输出对象
def mydeciphering(en_text):
    model = AES.MODE_ECB  # 定义模式
    aes = AES.new(tk, model)  # 创建一个aes对象
    text = aes.decrypt(en_text)  # 解密明文
    text=text.decode()
    while text[0]==' ':
        text=text[1:]
    text=eval(text)
    return text
#完整性验证函数，输入输出都是比特流
def integrity_check(text):
    h=hmac.new(tk,text,digestmod='MD5')
    return h.digest()
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
#执行一条sql语句，返回一个嵌套列表
def exesql_select(paralist):
    try:
        mysend(mypack(paralist,""))
        result=[]
        while 1:
            temp=myunpack(myrecv(),"")
            if(temp=="fin"):
                break
            result.append(temp)
        return result
    except Exception as e:
        raise e
def exesql_others(paralist):
    mysend(mypack("others",""))
    challenge=myunpack(myrecv(),"")#先解包出服务器发来的随机数
    mysend(mypack(paralist,challenge))#插入随机数计算消息认证码并发送
    if myunpack(myrecv(),challenge)=="successful":
        return 0
    else:
        return 1

#函数异常处理装饰器
def DECO(meg="",flag=0):
    def deco(fuc):
        def wrapper(*args):
            try:
                fuc(*args)
            except ConnectionResetError:
                wx.MessageBox("会话已过期，连接已断开！")
                return
            except ConnectionAbortedError:
                wx.MessageBox("会话已过期，连接已断开！")
                return
            except socket.timeout:
                warn = "程序运行中出现异常：\n"+meg+"详细信息：\n"+traceback.format_exc() + "请稍后重试或联系管理员！"
                wx.MessageBox(warn)
                if(flag==1):
                    clientSocket.close()
                    args[0].ancestor.Destroy()
                return
            except:
                warn = "程序运行中出现异常：\n"+meg+"详细信息：\n"+traceback.format_exc() + "请稍后重试或联系管理员！"
                try:
                    while 1:
                        if(len(clientSocket.recv(BUFSIZ))==0):
                            raise Exception("疑似收到close信息！")
                except:
                    wx.MessageBox(warn)
                    if (flag == 1):
                        clientSocket.close()
                        args[0].ancestor.Destroy()
                    return
        return wrapper
    return deco

# 通信函数
def mysend(meg):
    s=clientSocket
    meg=repr(meg).encode()
    head=struct.pack("i",len(meg))
    if(len(head+meg)>BUFSIZ):
        raise Exception("数据单次发送长度已超过缓冲区大小！")
    s.send(head+meg)

def myrecv():
    s=clientSocket
    head=s.recv(4)
    while 1:
        if len(head)==4:
            break
        else:
            head+=s.recv(4-len(head))
    length=struct.unpack("i",head)[0]
    if length>BUFSIZ-4:
        raise Exception("数据单次接收长度已超过缓冲区大小！")
    temp=s.recv(length)
    while 1:
        if len(temp)==length:
            break
        temp+=s.recv(length-len(temp))


    return ast.literal_eval(temp.decode())



# 日期合法检验函数
def validate(date_text):
    locale.setlocale(locale.LC_ALL, '')  # 此句用于校正wxPython下的现场，具体作用未知，可能会引起程序错误
    try:
        datetime.datetime.strptime(date_text, '%Y-%m-%d')
    except Exception as e:
        return 0
    else:
        return 1


# 小数合法检验函数
def is_positive_num(str):
    try:
        float(str)
    except:
        return 0
    else:
        if float(str) >= 0:
            return 1
        else:
            return 0

# 登录窗口
class entryframe(wx.Frame):
    def __init__(self, parent):
        self.output_flag = 0  # 顺利登录标志，实例成员，每建立一个对象都初始化一次
        self.output_tel = ""  # 登录成功者的手机号，实例成员，每建立一个对象都初始化一次
        self.output_identity = ""  # 登录者的身份
        wx.Frame.__init__(self, parent, title="系统登录", size=(1500,700))
        self.background()
        self.Bind(wx.EVT_CLOSE, self.on_close, self)  # 单击关闭按钮时确认
        self.Center()
        self.Show()
    def background(self):
        panel=wx.Panel
        image_file = 'cover.jpg'
        to_bmp_image = wx.Image(image_file, wx.BITMAP_TYPE_ANY).ConvertToBitmap()
        self.bitmap = wx.StaticBitmap(self, -1, to_bmp_image, (0, 0))
        login(self)
    def on_close(self, event):
        if wx.MessageBox("确定退出应用？", style=wx.CANCEL) == wx.OK:
            self.Destroy()
        else:
            return




class login(wx.Frame):
    def __init__(self,parent):
        wx.Frame.__init__(self, parent, size=(500, 300),pos=(900,300),style=wx.DEFAULT_FRAME_STYLE|wx.FRAME_FLOAT_ON_PARENT|wx.FRAME_TOOL_WINDOW)
        panel = wx.Panel(self)
        panel.SetBackgroundColour((100,200,255))
        self.parent=parent
        self.Bind(wx.EVT_CLOSE, self.on_close, self)  # 单击关闭按钮时确认
        # 三个按钮
        self.btn1 = wx.Button(parent=panel, label="新用户注册")
        self.Bind(wx.EVT_BUTTON, self.on_btn1, self.btn1)
        self.btn2 = wx.Button(parent=panel, label="登录")
        self.Bind(wx.EVT_BUTTON, self.on_btn2, self.btn2)
        self.btn3 = wx.Button(parent=panel, label="退出")
        self.Bind(wx.EVT_BUTTON, self.on_close, self.btn3)
        # 三个静态文本标签
        self.stxt_tel = wx.StaticText(panel, label="用户名（手机号）：")
        self.stxt_password = wx.StaticText(panel, label="密码：")
        self.stxt_id = wx.StaticText(panel, label="您的身份：")
        # 三个输入框
        self.txt_tel = wx.TextCtrl(panel)
        self.txt_password = wx.TextCtrl(panel,style=wx.TE_PASSWORD)
        choices = ["顾客", "店家"]
        self.combobox = wx.ComboBox(panel, choices=choices)
        # 表格布局
        grid = wx.GridSizer(4, 2, 30, 30)
        grid.Add(self.stxt_tel, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.txt_tel, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.stxt_password, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.txt_password, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.stxt_id, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.combobox, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.btn2, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.btn3, 0, flag=wx.ALIGN_CENTER)
        # 整体布局
        box_m = wx.BoxSizer(wx.VERTICAL)
        box_m.Add(self.btn1, 0, wx.ALIGN_RIGHT)
        box_m.Add(grid, 0, wx.ALIGN_CENTER)
        panel.SetSizer(box_m)
        #显示
        self.Show()


    def on_btn1(self, event):
        dialog1 = registerframe(self)

    def on_btn2(self, event):
        try:
            # 输入判空
            input_tel = self.txt_tel.GetValue()
            if (input_tel == ""):
                wx.MessageBox("用户名不能为空！")
                return
            input_password = self.txt_password.GetValue()
            if (input_password == ""):
                wx.MessageBox("密码不能为空！")
                return
            input_id = self.combobox.GetStringSelection()
            if input_id == "顾客"or input_id=="店家":
                pass
            else:
                wx.MessageBox("请选择您的身份！")
                return
            global clientSocket
            clientSocket=socket.socket()
            clientSocket.connect(ADDR)
            clientSocket.settimeout(5)
            mysend('1')
            # mysend和myrecv是自己设计的发送/接收函数
            mysend(input_id)#发送用户身份标识（顾客还是店主）
            mysend(input_tel)#发送手机号，即主键
            cha = myrecv()#cha代表challengeA，即服务器向客户端发送的挑战
            #如果服务器未发送随机数，则证明该用户不存在，断开连接并返回
            if cha == 'not exist':
                wx.MessageBox("用户不存在！")
                clientSocket.close()
                return
            #将密码和cha拼接起来做MD5
            local_md5_cha = hashlib.md5((input_password + str(cha)).encode()).digest()
            #chb（即challengeB)是客户端向服务器发送的挑战
            chb = random.randint(CH_LOW, CH_HIGH)
            #客户端挑战应答
            mysend(local_md5_cha)
            #客户端发送挑战
            mysend(chb)
            #客户端接收服务器的挑战应答
            rev_md5_chb = myrecv()
            #服务器未发送挑战应答，则说明密码不对，断开连接并返回
            if rev_md5_chb == 'not right':
                wx.MessageBox("用户名和密码不匹配！")
                clientSocket.close()
                return
            #将密码和chb拼接起来做MD5
            local_md5_chb = hashlib.md5((input_password + str(chb)).encode()).digest()
            #如果服务器的挑战应答和预计的不相符，说明服务器身份异常，断开连接并返回
            if rev_md5_chb != local_md5_chb:
                wx.MessageBox("服务器身份异常，请联系管理员！")
                clientSocket.close()
                return
            #生成临时会话密钥
            global tk
            tk=maketk(input_password,cha,chb)
            self.parent.output_flag = 1
            self.parent.output_tel = input_tel
            self.parent.output_identity = input_id
            self.parent.Destroy()
            return

        except Exception as e:
            clientSocket.close()
            if str(e)[0:16]=='[WinError 10065]':
                wx.MessageBox("无法连接到服务器，请检查网络设置。")
            else:
                warn="登录失败，已断开连接！\n详细信息：\n"+traceback.format_exc()
                wx.MessageBox(warn)

    def on_close(self, event):
        if wx.MessageBox("确定退出应用？", style=wx.CANCEL) == wx.OK:
            self.parent.Destroy()
        else:
            return



# 注册窗口
class registerframe(wx.Dialog):
    def __init__(self, parent):
        wx.Dialog.__init__(self, parent, title="新用户注册", size=(400, 400))
        self.Center()
        self.initUI()
        self.ShowModal()

    def initUI(self):
        panel = wx.Panel(self)
        # 元件建立
        self.stxt_tel = wx.StaticText(panel, label="手机号：")
        self.txt_tel = wx.TextCtrl(panel)
        self.stxt_name = wx.StaticText(panel, label="真实姓名：")
        self.txt_name = wx.TextCtrl(panel)
        self.stxt_ID = wx.StaticText(panel, label="身份证号：")
        self.txt_ID = wx.TextCtrl(panel)
        self.stxt_password1 = wx.StaticText(panel, label="密码：")
        self.txt_password1 = wx.TextCtrl(panel,style=wx.TE_PASSWORD)
        self.stxt_password2 = wx.StaticText(panel, label="确认密码：")
        self.txt_password2 = wx.TextCtrl(panel,style=wx.TE_PASSWORD)
        self.stxt_id = wx.StaticText(panel, label="您的身份：")
        choices = ["顾客", "店家"]
        self.combobox = wx.ComboBox(panel, choices=choices)
        self.btn_register = wx.Button(parent=panel, label="注册")
        self.Bind(wx.EVT_BUTTON, self.on_btn_register, self.btn_register)
        self.btn_cancel = wx.Button(parent=panel, label="取消")
        self.Bind(wx.EVT_BUTTON, self.on_btn_cancel, self.btn_cancel)

        # 表格布局
        grid = wx.GridSizer(7, 2, 0, 0)
        grid.Add(self.stxt_tel, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.txt_tel, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.stxt_name, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.txt_name, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.stxt_ID, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.txt_ID, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.stxt_password1, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.txt_password1, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.stxt_password2, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.txt_password2, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.stxt_id, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.combobox, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.btn_register, 0, flag=wx.ALIGN_CENTER)
        grid.Add(self.btn_cancel, 0, flag=wx.ALIGN_CENTER)
        panel.SetSizer(grid)

    def on_btn_register(self, event):
        try:
            txt_tuple = (self.txt_tel, self.txt_name, self.txt_ID, self.txt_password1, self.txt_password2)  # 存放所有文本框对象
            input_list = []  # 存放所有文本框的返回值
            for i in range(5):
                ele = txt_tuple[i].GetValue()
                if ele == "":
                    wx.MessageBox("请完整输入信息！")
                    return
                else:
                    input_list.append(ele)
            if input_list[3] != input_list[4]:
                wx.MessageBox("两次输入的密码不同！")
                return
            input_id = self.combobox.GetStringSelection()
            global clientSocket
            if input_id == "顾客":
                clientSocket = socket.socket()
                clientSocket.connect(ADDR)
                clientSocket.settimeout(5)
                mysend('2')
                #cha即challengeA
                cha=random.randint(CH_LOW,CH_HIGH)#生成随机数cha
                mysend(rsa_encryption(str(cha)+'*'+repr(input_list[0])))#将cha和用户手机号拼接起来，公钥加密后发送
                result1=myrecv()
                #如果结果是MD5（failed+cha）说明手机号已被注册，断开连接并返回
                if result1==hashlib.md5(("failed"+str(cha)).encode()).digest():
                    wx.MessageBox("此手机号已被注册！")
                    clientSocket.close()
                    return
                #如果结果是MD5（successful+cha）说明可以注册，进行后续程序
                elif  result1==hashlib.md5((("successful")+str(cha)).encode()).digest():
                    pass
                else:
                #如果都不是说明发生了异常，因为只有服务器有私钥，可以解密得到cha，所以无法给出正确回复的就是假服务器
                    raise Exception("手机号检测过程中出现异常！")
                #生成随机数chb
                chb=random.randint(CH_LOW,CH_HIGH)
                #将chb和其它用户信息（如身份证号、姓名等）拼接起来，公钥加密后发送，之后与上面一样
                mysend(rsa_encryption((str(chb)+'*'+repr((input_list[0], input_list[1], input_list[2], input_list[3])))))
                result2=myrecv()
                if result2==hashlib.md5(("successful"+str(chb)).encode()).digest():
                    wx.MessageBox("注册成功！")
                    clientSocket.close()
                    self.Close()
                    return
                else:
                    raise Exception("创建用户过程失败！")
            elif input_id == "店家":
                dlg = wx.TextEntryDialog(self, message="请设置您的店铺名称：", caption="店名设置")
                if dlg.ShowModal() == wx.ID_CANCEL:
                    return
                input_sname = dlg.GetValue()
                if input_sname == "":
                    wx.MessageBox("店名不能为空！")
                    return
                clientSocket = socket.socket()
                clientSocket.connect(ADDR)
                clientSocket.settimeout(5)
                mysend('3')
                cha = random.randint(CH_LOW, CH_HIGH)
                mysend(rsa_encryption(str(cha) + '*' + repr(input_list[0])))
                result1 = myrecv()
                if result1==hashlib.md5(("failed"+str(cha)).encode()).digest():
                    wx.MessageBox("此手机号已被注册！")
                    clientSocket.close()
                    return
                elif  result1==hashlib.md5((("successful")+str(cha)).encode()).digest():
                    pass
                else:
                    raise Exception("手机号检测过程中出现异常！")
                chb = random.randint(CH_LOW, CH_HIGH)
                mysend(rsa_encryption((str(chb) + '*' + repr((input_list[0], input_list[1], input_list[2], input_list[3], input_sname)))))
                result2 = myrecv()
                if result2 == hashlib.md5(("successful" + str(chb)).encode()).digest():
                    wx.MessageBox("注册成功！")
                    clientSocket.close()
                    self.Close()
                    return
                else:
                    raise Exception("创建用户过程失败！")
            else:
                wx.MessageBox("请选择您的身份！")
                return
        except Exception as e:
            clientSocket.close()
            if str(e)[0:16] == '[WinError 10065]':
                wx.MessageBox("无法连接到服务器，请检查网络设置。")
            elif str(e)=="手机号检测过程中出现异常！":
                wx.MessageBox("注册失败，请稍后重试或联系管理员。")
            else:
                warn = "注册中出现未知异常，请尝试登录以确定是否注册成功！\n详细信息：\n" + traceback.format_exc()
                wx.MessageBox(warn)
                self.Close()

    def on_btn_cancel(self, event):
        self.Close()


# 顾客端程序主窗体
class customerframe(wx.Frame):
    def __init__(self, parent, tel):
        self.tel = tel
        wx.Frame.__init__(self, parent, title="网上书店系统客户端程序", size=(1500, 700))
        self.Bind(wx.EVT_CLOSE, self.on_close, self)  # 退出前确认
        self.initUI(self.tel)
        self.Center()
        self.Show()

    def initUI(self, tel):
        nb = wx.Notebook(self)
        nb.AddPage(cu_panel1(nb, tel), "找书")
        nb.AddPage(cu_panel2(nb, tel), "订单")
        nb.AddPage(cu_panel3(nb, tel, self), "个人信息维护")

    def on_close(self, event):
        if wx.MessageBox("确定退出当前账号？", style=wx.CANCEL) == wx.OK:
            clientSocket.close()
            self.Destroy()
        else:
            return


# 顾客端找书页面
class cu_panel1(wx.Panel):


    def __init__(self, parent, tel):
        self.tel = tel
        wx.Panel.__init__(self,parent)
        self.SetBackgroundColour((100,255,255))
        # 提示语及其字体设置
        tip = wx.StaticText(self, label="单击“查询”显示书单。可勾选查询条件进行筛查，支持模糊搜索。", size=(900, 25))
        tip.SetBackgroundColour(None)
        font = wx.Font(13, wx.DEFAULT, wx.SLANT, wx.LIGHT)
        tip.SetFont(font)
        #创建初级参数列表，可供单选按钮使用
        self.firstpara=[]
        # 创建复选框
        self.cb_list = []
        self.cb_label = ["店铺名：", "书号：", "书名：", "作者：", "出版社："]
        for i in range(5):
            self.cb_list.append(wx.CheckBox(self, label=self.cb_label[i]))
        # 创建输入文本框
        self.input_list = []
        for i in range(5):
            self.input_list.append(wx.TextCtrl(self))
        # 前五个复选框和输入文本框拼接
        boxsizer1 = wx.BoxSizer(wx.HORIZONTAL)
        for i in range(5):
            boxsizer1.Add(self.cb_list[i], 0)
            boxsizer1.Add(self.input_list[i], 0)
            boxsizer1.AddSpacer(20)
        # 日期项目创建
        self.cb_pdate = wx.CheckBox(self, label="出版日期（格式：年-月-日）：")
        self.input_data1 = wx.TextCtrl(self)
        dao = wx.StaticText(self, label='——')
        self.input_data2 = wx.TextCtrl(self)
        # 添加日期项目
        boxsizer1.Add(self.cb_pdate, 0)
        boxsizer1.Add(self.input_data1, 0)
        boxsizer1.Add(dao, 0)
        boxsizer1.Add(self.input_data2, 0)
        # 添加查询按键和排序选项
        self.btn_select = wx.Button(self, label="查询", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_select, self.btn_select)
        sort = ['销量', '售价升序', '售价降序']
        self.rbtn_sort = wx.RadioBox(self, choices=sort, majorDimension=1, style=wx.RA_SPECIFY_ROWS)
        self.Bind(wx.EVT_RADIOBOX, self.on_rbtn_sort, self.rbtn_sort)
        # 添加订单按键
        self.btn_addor = wx.Button(self, label="添加订单", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_addor, self.btn_addor)
        # 查询按键、添加订单和排序选项的布局
        boxsizer2 = wx.BoxSizer(wx.HORIZONTAL)
        boxsizer2.Add(self.btn_select, 0)
        boxsizer2.Add(self.btn_addor)
        boxsizer2.AddSpacer(200)
        boxsizer2.Add(self.rbtn_sort, 0)
        boxsizer2.AddSpacer(130)
        # 创建表，设置属性
        self.grid_book = wx.grid.Grid(self, size=(1000, 450))
        self.grid_book.CreateGrid(50, 11)
        property = ['书号', '书名', '作者', '出版社', '出版日期', '版次', '定价', '销售店', '店主手机号', '售价', '销量']
        for i in range(11):
            self.grid_book.SetColLabelValue(i, property[i])

        # 创建主布局器进行布局
        boxsizer_m1 = wx.BoxSizer(wx.VERTICAL)
        boxsizer_m1.Add(tip, 0, wx.ALIGN_LEFT)
        boxsizer_m1.Add(boxsizer1, 0, wx.ALIGN_CENTER)
        boxsizer_m1.AddSpacer(10)
        boxsizer_m1.Add(boxsizer2, 0, wx.ALIGN_RIGHT)
        boxsizer_m1.Add(self.grid_book, 0, wx.ALIGN_CENTER)
        self.SetSizer(boxsizer_m1)
    @DECO()
    def on_btn_select(self, event):
        paralist=[-1,-1,-1,-1,-1,-1,-1,-1]
        #raise Exception("582")
        for i in range(5):
            if self.cb_list[i].GetValue():
                paralist[i]=self.input_list[i].GetValue()
        if self.cb_pdate.GetValue():
            paralist[5]=self.input_data1.GetValue()
            paralist[6]=self.input_data2.GetValue()
        self.firstpara = paralist.copy()  # 初级参数列表，可以让单选按钮调用
        if self.rbtn_sort.GetStringSelection() == "销量":
            paralist[7]=0
        elif self.rbtn_sort.GetStringSelection() == "售价升序":
            paralist[7]=1
        else:
            paralist[7]=2


        paralist.insert(0,1)
        result = exesql_select(paralist)
        self.grid_book.ClearGrid()
        if len(result) == 0:
            wx.MessageBox("未查询到任何结果，请检查您的查询条件是否合法！")
            return
        for i in range(len(result)):
            for j in range(11):
                self.grid_book.SetCellValue(i, j, str(result[i][j]))
            if i == 49:
                break
        self.grid_book.AutoSizeColumns()
        return



    @DECO()
    def on_rbtn_sort(self, event):
        if(self.firstpara==[]):
            return
        paralist=self.firstpara.copy()
        if self.rbtn_sort.GetStringSelection() == "销量":
            paralist[7] = 0
        elif self.rbtn_sort.GetStringSelection() == "售价升序":
            paralist[7] = 1
        else:
            paralist[7] = 2
        paralist.insert(0, 1)
        result = exesql_select(paralist)
        self.grid_book.ClearGrid()
        if len(result) == 0:
            wx.MessageBox("未查询到任何结果，请检查您的查询条件是否合法！")
            return
        for i in range(len(result)):
            for j in range(11):
                self.grid_book.SetCellValue(i, j, str(result[i][j]))
            if i == 49:
                break
        self.grid_book.AutoSizeColumns()
        return

    def on_btn_addor(self, event):
        addorder(self, self.tel)


# “添加订单”弹出窗口
class addorder(wx.Dialog):
    def __init__(self, parent, tel):
        wx.Dialog.__init__(self, parent, title="添加订单", size=(400, 300))
        self.tel = tel
        panel = wx.Panel(self)
        self.Center()
        self.stxtlist = []
        self.stxtlabel = ["书号：", "店主手机号：", "数量："]
        self.txtlist = []
        gridsizer = wx.GridSizer(4, 2, 0, 0)
        for i in range(3):
            self.stxtlist.append(wx.StaticText(panel, label=self.stxtlabel[i]))
            gridsizer.Add(self.stxtlist[i], 0, flag=wx.ALIGN_CENTER)
            self.txtlist.append(wx.TextCtrl(panel))
            gridsizer.Add(self.txtlist[i], 0, flag=wx.ALIGN_CENTER)
        self.btn_ok = wx.Button(panel, label="确定")
        self.Bind(wx.EVT_BUTTON, self.on_btn_ok, self.btn_ok)
        self.btn_cal = wx.Button(panel, label="取消")
        self.Bind(wx.EVT_BUTTON, self.on_btn_cal, self.btn_cal)
        gridsizer.Add(self.btn_ok, 0, flag=wx.ALIGN_CENTER)
        gridsizer.Add(self.btn_cal, 0, flag=wx.ALIGN_CENTER)
        panel.SetSizer(gridsizer)
        self.Show()
    @DECO("订单提交过程中出现异常，请到“订单”页面手动查看订单是否提交成功！\n")
    def on_btn_ok(self, event):
        inputlist = []
        for i in range(3):
            inputlist.append(self.txtlist[i].GetValue())
            if inputlist[i] == "":
                wx.MessageBox("请完整填写数据！")
                return
        # 输入安全检查
        if not (inputlist[2].isdigit() and int(inputlist[2]) > 0):
            wx.MessageBox("数量必须为正整数！")
            return
        result = exesql_select([2,inputlist[0]])
        if result==[]:
            wx.MessageBox("书号不存在！")
            return
        result = exesql_select([3,inputlist[1]])
        if result==[]:
            wx.MessageBox("店铺不存在！")
            return
        result = exesql_select([4,inputlist[1], inputlist[0]])
        if result==[]:
            wx.MessageBox("该店不售此书！")
            return
        # 执行插入
        result=result[0]
        total = int(inputlist[2]) * result[2]
        if (exesql_others([5, inputlist[1], inputlist[0], inputlist[2], str(total)]))==0:
            wx.MessageBox("订单已提交！")
            self.Close()
        else:
            wx.MessageBox("订单提交过程中出现异常，请到“查看订单”页面手动查看订单是否提交成功！")


    def on_btn_cal(self, event):
        self.Close()


# 顾客端“查看订单”页面。
class cu_panel2(wx.Panel):
    def __init__(self, parent, tel):
        self.tel = tel
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour((100,255,255))
        self.btn_display = wx.Button(self, label="显示订单/刷新", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_display, self.btn_display)
        # 创建表，设置属性
        self.grid = wx.grid.Grid(self, size=(800, 450))
        self.grid.CreateGrid(50, 9)
        property = ['顾客名', '顾客电话', '店名', '店主电话', '书名', '书号', '订购量', '订单价格', '下单日期']
        for i in range(9):
            self.grid.SetColLabelValue(i, property[i])
        boxsizer = wx.BoxSizer(wx.VERTICAL)
        boxsizer.Add(self.btn_display, 0, wx.ALIGN_CENTER)
        boxsizer.AddSpacer(30)
        boxsizer.Add(self.grid, 0, wx.ALIGN_CENTER)
        self.SetSizer(boxsizer)
    @DECO()
    def on_btn_display(self, event):
        result = exesql_select([6])
        self.grid.ClearGrid()
        if len(result) == 0:
            wx.MessageBox("当前暂无订单。")
            return
        for i in range(len(result)):
            for j in range(9):
                self.grid.SetCellValue(i, j, str(result[i][j]))
            if i == 49:
                break
        self.grid.AutoSizeColumns()
        return


# 顾客端“个人信息维护”页面
class cu_panel3(wx.Panel):
    @DECO("个人信息加载失败，请稍后重新登录或联系管理员！\n",1)
    def __init__(self, parent, tel, ancestor):
        self.tel = tel
        self.ancestor = ancestor  # 传入父窗口的地址
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour((100, 255, 255))
        # 准备显示个人信息于只读文本框
        result = exesql_select([7])
        result=result[0]#将返回的嵌套元组变为元组
        self.stxtlist = []
        self.stxtlabel = ["姓名：", "手机号：", "身份证号："]
        self.txtlist = []
        gridsizer = wx.GridSizer(5, 2, 40, 40)
        for i in range(3):
            self.stxtlist.append(wx.StaticText(self, label=self.stxtlabel[i]))
            gridsizer.Add(self.stxtlist[i], 0, flag=wx.ALIGN_CENTER)
            self.txtlist.append(wx.TextCtrl(self, size=(135, 20), style=wx.TE_READONLY))
            gridsizer.Add(self.txtlist[i], 0, flag=wx.ALIGN_CENTER)
            self.txtlist[i].SetValue(result[i])
        self.btnlist = []
        self.btnlabel = ["换绑手机号", "修改密码", "退出登录", "注销账号"]

        for i in range(4):
            self.btnlist.append(wx.Button(self, label=self.btnlabel[i]))
            gridsizer.Add(self.btnlist[i], 0, flag=wx.ALIGN_CENTER)
        boxsizer = wx.BoxSizer(wx.VERTICAL)
        boxsizer.AddSpacer(100)
        boxsizer.Add(gridsizer, 0, flag=wx.ALIGN_CENTER)
        self.SetSizer(boxsizer)
        self.Bind(wx.EVT_BUTTON, self.on_btn0, self.btnlist[0])
        self.Bind(wx.EVT_BUTTON, self.on_btn1, self.btnlist[1])
        self.Bind(wx.EVT_BUTTON, self.on_btn2, self.btnlist[2])
        self.Bind(wx.EVT_BUTTON, self.on_btn3, self.btnlist[3])
    def check_id(self):
        dlg = wx.TextEntryDialog(self, message="请先输入密码以确认身份！",style=wx.CANCEL|wx.OK|wx.TE_PASSWORD)
        dlg.Center()
        if dlg.ShowModal() == wx.ID_CANCEL:
            return 0
        input_password = dlg.GetValue()
        cur_password = exesql_select([8])[0]  # 注意：cur_password是元组类型
        if input_password != cur_password[0]:
            wx.MessageBox("密码不正确！")
            return 0
        else:
            return 1
    @DECO("手机号换绑过程中出现未知异常，现在需要您重新登录以测试是否换绑成功！\n",1)
    def on_btn0(self, event):
        if self.check_id() == 0:
            return
        dlg = wx.TextEntryDialog(self, message="请输入新手机号：")
        if dlg.ShowModal() == wx.ID_CANCEL:
            return
        input_tel = dlg.GetValue()
        if input_tel == "":
            wx.MessageBox("新手机号不能为空！")
            return
        result1 = exesql_select([9,input_tel])
        if len(result1)!=0:
            wx.MessageBox("此手机号已被注册！")
            return
        if exesql_others([10,input_tel])==0:
            wx.MessageBox("手机号已成功换绑！\n重新登录即可生效。")
        else:
            wx.MessageBox("手机号换绑过程中出现未知异常，现在需要您重新登录以测试是否换绑成功！")
        clientSocket.close()
        self.ancestor.Destroy()
    @DECO("密码修改过程中出现未知异常，现在需要您重新登录以测试密码修改是否成功！",1)
    def on_btn1(self, event):
        if self.check_id() == 0:
            return
        while 1:
            dlg1 = wx.TextEntryDialog(self, message="请输入新密码：",style=wx.OK|wx.CANCEL|wx.TE_PASSWORD)
            dlg1.Center()
            if dlg1.ShowModal() == wx.ID_CANCEL:
                return
            input1 = dlg1.GetValue()
            if input1 == "":
                wx.MessageBox("新密码不能为空！")
                dlg1.Destroy()
                continue
            dlg1.Destroy()
            dlg2 = wx.TextEntryDialog(self, message="请确认您的新密码：",style=wx.OK|wx.CANCEL|wx.TE_PASSWORD)
            dlg2.Center()
            if dlg2.ShowModal() == wx.ID_CANCEL:
                return
            input2 = dlg2.GetValue()
            if input1 != input2:
                wx.MessageBox("两次输入的密码不一致！")
                dlg2.Destroy()
                continue
            break
        if exesql_others([29,input1])==0:
            wx.MessageBox("密码修改成功！")
        else:
            wx.MessageBox("密码修改过程中出现未知异常，现在需要您重新登录以测试密码修改是否成功！")
            clientSocket.close()
            self.ancestor.Destroy()

    def on_btn2(self, event):
        self.ancestor.Close()
    @DECO("注销过程中出现未知异常，请尝试重新登录以测试是否已注销成功！\n",1)
    def on_btn3(self, event):
        if self.check_id() == 0:
            return
        if wx.MessageBox("注销后账户的所有信息都将删除,不可恢复！\n是否继续？", style=wx.CANCEL) == wx.OK:
            if exesql_others([11])==0:
                wx.MessageBox("账户已注销！")
            else:
                wx.MessageBox("注销过程中出现未知异常，请尝试重新登录以测试是否已注销成功！")
            clientSocket.close()
            self.ancestor.Destroy()
        else:
            return


# 店主端程序主窗体
class storeframe(wx.Frame):
    def __init__(self, parent, tel):
        self.tel = tel
        wx.Frame.__init__(self, parent, title="网上书店系统店主端程序", size=(1500, 700))
        self.Bind(wx.EVT_CLOSE, self.on_close, self)  # 退出前确认
        self.initUI(self.tel)
        self.Center()
        self.Show()

    def initUI(self, tel):
        nb = wx.Notebook(self)
        nb.AddPage(st_panel1(nb, tel), "我的书库")
        nb.AddPage(st_panel2(nb, tel), "订单")
        nb.AddPage(st_panel3(nb, tel, self), "个人信息维护")

    def on_close(self, event):
        if wx.MessageBox("确定退出当前账号？", style=wx.CANCEL) == wx.OK:
            clientSocket.close()
            self.Destroy()
        else:
            return


# 店主端“书库”页面
class st_panel1(wx.Panel):
    def __init__(self, parent, tel):
        self.tel = tel
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour((100, 255, 255))
        # 按钮的操作和创建
        self.btn_display = wx.Button(self, label="显示书单/刷新", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_display, self.btn_display)
        self.btn_insert = wx.Button(self, label="添加图书", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_insert, self.btn_insert)
        self.btn_delete = wx.Button(self, label="删除图书", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_delete, self.btn_delete)
        self.btn_update = wx.Button(self, label="更改售价", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_update, self.btn_update)
        boxsizer1 = wx.BoxSizer(wx.HORIZONTAL)
        boxsizer1.Add(self.btn_display, 0, wx.ALIGN_CENTER)
        boxsizer1.Add(self.btn_insert, 0, wx.ALIGN_CENTER)
        boxsizer1.Add(self.btn_delete, 0, wx.ALIGN_CENTER)
        boxsizer1.Add(self.btn_update, 0, wx.ALIGN_CENTER)
        # 创建表，设置属性
        self.grid = wx.grid.Grid(self, size=(700, 450))
        self.grid.CreateGrid(50, 9)
        property = ['书号', '书名', '作者', '出版社', '出版日期', '版次', '定价', '售价', '销量']
        for i in range(9):
            self.grid.SetColLabelValue(i, property[i])
        boxsizer = wx.BoxSizer(wx.VERTICAL)
        boxsizer.Add(boxsizer1, 0, wx.ALIGN_CENTER)
        boxsizer.AddSpacer(30)
        boxsizer.Add(self.grid, 0, wx.ALIGN_CENTER)
        self.SetSizer(boxsizer)
    @DECO()
    def on_btn_display(self, event):
        result = exesql_select([12])
        self.grid.ClearGrid()
        if len(result) == 0:
            wx.MessageBox("当前暂无图书。")
            return
        for i in range(len(result)):
            for j in range(9):
                self.grid.SetCellValue(i, j, str(result[i][j]))
            if i == 49:
                break
        self.grid.AutoSizeColumns()
        return
    def on_btn_insert(self, event):
        insertbookframe(self, self.tel)
    @DECO("图书删除过程中出现未知异常，请报告管理员！\n")
    def on_btn_delete(self, event):
        while 1:
            dlg = wx.TextEntryDialog(self, message="请输入要删除书目的书号：")
            if dlg.ShowModal()== wx.ID_CANCEL:
                return
            input = dlg.GetValue()
            if input == "":
                wx.MessageBox("书号不能为空！")
                dlg.Destroy()
                continue
            dlg.Destroy()
            break
        result =exesql_select([13,input])
        if len(result) == 0:
            wx.MessageBox("无效书号！")
            return
        if exesql_others([14,input])==1:
            wx.MessageBox("图书删除过程中出现未知异常，请报告管理员！\n")
            return
        # 检查是否在销售列表和订单列表里仍有此书，如果没有，则级联删除此书
        result1 = exesql_select([15,input])
        result2 = exesql_select([16,input])
        if (len(result1)==0) and (len(result2)==0):
            if exesql_others([17,input])==1:
                wx.MessageBox("图书删除过程中出现未知异常，请报告管理员！\n")
                return
        wx.MessageBox("图书已删除！")
    @DECO("售价修改中出现未知异常，请手动查看是否修改成功！\n")
    def on_btn_update(self, event):
        while 1:
            dlg1 = wx.TextEntryDialog(self, message="请输入待修改书目的书号：")
            if dlg1.ShowModal() == wx.ID_CANCEL:
                return
            input1 = dlg1.GetValue()
            if input1 == "":
                wx.MessageBox("书号不能为空！")
                dlg1.Destroy()
                continue
            dlg1.Destroy()
            break
        result = exesql_select([13,[input1]])
        if len(result)==0:
            wx.MessageBox("无效书号！")
            return
        while 1:
            dlg2 = wx.TextEntryDialog(self, message="请输入售价：")
            if dlg2.ShowModal() == wx.ID_CANCEL:
                return
            input2 = dlg2.GetValue()
            if input2 == "":
                wx.MessageBox("售价不能为空！")
                dlg2.Destroy()
                continue
            if is_positive_num(input2) == 0:
                wx.MessageBox("售价输入不合法！")
                dlg2.Destroy()
                continue
            dlg2.Destroy()
            break
        if exesql_others([18,input2,input1])==1:
            wx.MessageBox("售价修改中出现未知异常，请手动查看是否修改成功！\n")
            return
        wx.MessageBox("售价已修改！")


# 店主端添加新书对话框
class insertbookframe(wx.Dialog):
    def __init__(self, parent, tel):
        wx.Dialog.__init__(self, parent, title="添加图书", size=(400, 400))
        self.tel = tel
        panel = wx.Panel(self)
        self.Center()
        self.stxtlist = []
        self.stxtlabel = ["书号：", "书名：", "作者：", "出版社", "出版日期（格式：年-月-日）：", "版次：", "定价：", "售价："]
        self.txtlist = []
        gridsizer = wx.GridSizer(9, 2, 0, 0)
        for i in range(8):
            self.stxtlist.append(wx.StaticText(panel, label=self.stxtlabel[i]))
            gridsizer.Add(self.stxtlist[i], 0, flag=wx.ALIGN_CENTER)
            self.txtlist.append(wx.TextCtrl(panel))
            gridsizer.Add(self.txtlist[i], 0, flag=wx.ALIGN_CENTER)
        self.btn_ok = wx.Button(panel, label="确定")
        self.Bind(wx.EVT_BUTTON, self.on_btn_ok, self.btn_ok)
        self.btn_cal = wx.Button(panel, label="取消")
        self.Bind(wx.EVT_BUTTON, self.on_btn_cal, self.btn_cal)
        gridsizer.Add(self.btn_ok, 0, flag=wx.ALIGN_CENTER)
        gridsizer.Add(self.btn_cal, 0, flag=wx.ALIGN_CENTER)
        panel.SetSizer(gridsizer)
        self.Show()
    @DECO("图书添加过程中出现未知异常，请刷新手动查看是否添加成功！\n")
    def on_btn_ok(self, event):
        inputlist = []
        for i in range(8):
            inputlist.append(self.txtlist[i].GetValue())
            if inputlist[i] == "":
                wx.MessageBox("请完整填写数据！")
                return
        # 输入安全检查
        if is_positive_num(inputlist[7]) == 0:
            wx.MessageBox("售价填写不合法！")
            return
        if is_positive_num(inputlist[6]) == 0:
            wx.MessageBox("定价填写不合法！")
            return
        if validate(inputlist[4]) == 0:
            wx.MessageBox("日期填写不合法！")
            return
        result = exesql_select([13,inputlist[0]])
        if len(result):
            wx.MessageBox("此书已在书库中！")
            return
        # 执行插入
        result = exesql_select([2,inputlist[0]])
        if len(result)==0:
            if exesql_others([19,inputlist[0], inputlist[1], inputlist[2], inputlist[3], inputlist[4], inputlist[5],
                        inputlist[6]]):
                wx.MessageBox("插入中出现未知异常，请手动查看是否插入成功！\n")
                return
        if exesql_others([20,inputlist[0], inputlist[7]]):
            wx.MessageBox("插入中出现未知异常，请手动查看是否插入成功！\n")
            return
        wx.MessageBox("添加成功！")
        self.Close()

    def on_btn_cal(self, event):
        self.Close()


# 店主端“订单”页面
class st_panel2(wx.Panel):
    def __init__(self, parent, tel):
        self.tel = tel
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour((100, 255, 255))
        self.btn_display = wx.Button(self, label="显示订单/刷新", size=(200, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_display, self.btn_display)
        # 创建表，设置属性
        self.grid = wx.grid.Grid(self, size=(650, 450))
        self.grid.CreateGrid(50, 7)
        property = ['顾客名', '顾客电话', '书名', '书号', '订购量', '订单价格', '下单日期']
        for i in range(7):
            self.grid.SetColLabelValue(i, property[i])
        boxsizer = wx.BoxSizer(wx.VERTICAL)
        boxsizer.Add(self.btn_display, 0, wx.ALIGN_CENTER)
        boxsizer.AddSpacer(30)
        boxsizer.Add(self.grid, 0, wx.ALIGN_CENTER)
        self.SetSizer(boxsizer)
    @DECO()
    def on_btn_display(self, event):
        result = exesql_select([21])
        self.grid.ClearGrid()
        if len(result) == 0:
            wx.MessageBox("当前暂无订单。")
            return
        for i in range(len(result)):
            for j in range(7):
                self.grid.SetCellValue(i, j, str(result[i][j]))
            if i == 49:
                break
        self.grid.AutoSizeColumns()
        return


# 店主端“个人信息维护”页面
class st_panel3(wx.Panel):
    @DECO("个人信息加载失败，请稍后重新登录或联系管理员！\n",1)
    def __init__(self, parent, tel, ancestor):
        self.tel = tel
        self.ancestor = ancestor  # 传入父窗口的地址
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour((100, 255, 255))
        # 准备显示个人信息于只读文本框
        result = exesql_select([22])[0]

        self.stxtlist = []
        self.stxtlabel = ["店主姓名：", "手机号：", "身份证号：", "店铺名:"]
        self.txtlist = []
        gridsizer = wx.GridSizer(6, 2, 40, 40)
        for i in range(4):
            self.stxtlist.append(wx.StaticText(self, label=self.stxtlabel[i]))
            gridsizer.Add(self.stxtlist[i], 0, flag=wx.ALIGN_CENTER)
            self.txtlist.append(wx.TextCtrl(self, size=(135, 20), style=wx.TE_READONLY))
            gridsizer.Add(self.txtlist[i], 0, flag=wx.ALIGN_CENTER)
            self.txtlist[i].SetValue(result[i])
        self.btnlist = []
        self.btnlabel = ["换绑手机号", "修改密码", "退出登录", "注销账号"]
        for i in range(4):
            self.btnlist.append(wx.Button(self, label=self.btnlabel[i]))
            gridsizer.Add(self.btnlist[i], 0, flag=wx.ALIGN_CENTER)
        self.btn_resetsname = wx.Button(self, label="更改店铺名", size=(250, 30))
        self.Bind(wx.EVT_BUTTON, self.on_btn_resetsname, self.btn_resetsname)
        boxsizer = wx.BoxSizer(wx.VERTICAL)
        boxsizer.AddSpacer(90)
        boxsizer.Add(gridsizer, 0, flag=wx.ALIGN_CENTER)
        boxsizer.AddSpacer(30)
        boxsizer.Add(self.btn_resetsname, 0, flag=wx.ALIGN_CENTER)
        self.SetSizer(boxsizer)
        self.Bind(wx.EVT_BUTTON, self.on_btn0, self.btnlist[0])
        self.Bind(wx.EVT_BUTTON, self.on_btn1, self.btnlist[1])
        self.Bind(wx.EVT_BUTTON, self.on_btn2, self.btnlist[2])
        self.Bind(wx.EVT_BUTTON, self.on_btn3, self.btnlist[3])

    def check_id(self):
        dlg = wx.TextEntryDialog(self, message="请先输入密码以确认身份！",style=wx.OK|wx.CANCEL|wx.TE_PASSWORD)
        dlg.Center()
        if dlg.ShowModal() == wx.ID_CANCEL:
            return 0
        input_password = dlg.GetValue()
        cur_password = exesql_select([23])[0]  # 注意：cur_password是元组类型
        if input_password != cur_password[0]:
            wx.MessageBox("密码不正确！")
            return 0
        else:
            return 1
    @DECO("手机号换绑中出现未知异常，请重新登录以验证是否换绑成功！\n",1)
    def on_btn0(self, event):
        if self.check_id() == 0:
            return
        dlg = wx.TextEntryDialog(self, message="请输入新手机号：")
        if dlg.ShowModal() == wx.ID_CANCEL:
            return
        input_tel = dlg.GetValue()
        if input_tel == "":
            wx.MessageBox("新手机号不能为空！")
            return
        result1 = exesql_select([24,input_tel])
        if len(result1)!=0:
            wx.MessageBox("此手机号已被注册！")
            return
        if exesql_others([25,input_tel]):
            wx.MessageBox("手机号换绑中出现未知异常，请重新登录以验证是否换绑成功！\n")
        else:
            wx.MessageBox("手机号已成功换绑！\n重新登录即可生效。")
        clientSocket.close()
        self.ancestor.Destroy()
    @DECO("密码修改中出现未知异常，请重新登录以验证是否修改成功！\n",1)
    def on_btn1(self, event):
        if self.check_id() == 0:
            return
        while 1:
            dlg1 = wx.TextEntryDialog(self, message="请输入新密码：",style=wx.OK|wx.CANCEL|wx.TE_PASSWORD)
            dlg1.Center()
            if dlg1.ShowModal() == wx.ID_CANCEL:
                return
            input1 = dlg1.GetValue()
            if input1 == "":
                wx.MessageBox("新密码不能为空！")
                dlg1.Destroy()
                continue
            dlg1.Destroy()
            dlg2 = wx.TextEntryDialog(self, message="请确认您的新密码：",style=wx.OK|wx.CANCEL|wx.TE_PASSWORD)
            dlg2.Center()
            if dlg2.ShowModal() == wx.ID_CANCEL:
                return
            input2 = dlg2.GetValue()
            if input1 != input2:
                wx.MessageBox("两次输入的密码不一致！")
                dlg2.Destroy()
                continue
            break
        if exesql_others([26,input1]):
            wx.MessageBox("密码修改中出现未知异常，请重新登录以验证是否修改成功！\n")
            clientSocket.close()
            self.ancestor.Destroy()
        wx.MessageBox("密码修改成功！")

    def on_btn2(self, event):
        self.ancestor.Close()
    @DECO("注销中出现未知异常，请重新登录以验证是否注销成功！\n",1)
    def on_btn3(self, event):
        if self.check_id() == 0:
            return
        if wx.MessageBox("注销后账户的所有信息都将删除,不可恢复！\n是否继续？", style=wx.CANCEL) == wx.OK:
            if exesql_others([27]):
                wx.MessageBox("注销中出现未知异常，请重新登录以验证是否注销成功！")
            else:
                wx.MessageBox("账户已注销！")
            clientSocket.close()
            self.ancestor.Destroy()
        else:
            return
    @DECO("更改中出现未知异常，请人工查看是否修改成功！\n")
    def on_btn_resetsname(self, event):
        dlg = wx.TextEntryDialog(self, message="请输入新店铺名：")
        if dlg.ShowModal() == wx.ID_CANCEL:
            return
        input = dlg.GetValue()
        if input == "":
            wx.MessageBox("新店名不能为空！")
            return
        if exesql_others([28,input]):
            wx.MessageBox("更改中出现未知异常，请人工查看是否修改成功！")
            return
        else:
            self.txtlist[3].SetValue(input)
            wx.MessageBox("店名已更改！")


if __name__ == '__main__':
    try:
        app = wx.App()
        with open("./clientconfig","r") as file:
            ADDR=eval(file.readline())
            BUFSIZ = eval(file.readline())
            CH_LOW = eval(file.readline())
            CH_HIGH = eval(file.readline())


        while True:
            en_frame = entryframe(None)
            app.MainLoop()
            print(en_frame.output_flag, en_frame.output_tel, en_frame.output_identity)

            if en_frame.output_flag == 0:
                sys.exit()
            if en_frame.output_identity == "顾客":

                cu_frame = customerframe(None, en_frame.output_tel)
                app.MainLoop()
            else:

                st_frame = storeframe(None, en_frame.output_tel)
                app.MainLoop()
    except Exception as e:
        wx.MessageBox("程序运行中出现未知的严重错误，现已停止运行！\n"+traceback.format_exc())
        sys.exit(1)

'''
程序缺陷：
1.字符串类型的数据除了会影响实体完整性的项目，都没有检查输入合法性
2.按出版日期查找书时没有判断输入日期合法性
3.缺少登录欢迎界面
4.wxPython下的locale是怎么回事
5.提交订单时没能直接显示价格
6.目前三号书店多一本杨波的现代密码学
7.增删改书的时候只能设置阻止模式
'''
#通信函数ack版备份
'''
def mysend(meg):
    s=clientSocket
    s.send(repr(meg).encode())
    if s.recv(3).decode()== 'ack':
        return
    else:
        raise Exception("未收到确认，数据传送失败！")


def myrecv():
    s=clientSocket
    string = s.recv(BUFSIZ).decode()
    if len(string) == 0:  # eval在处理空字符串时会返回EOF错误
        ans = ""
    else:
        ans = eval(string)
    s.send("ack".encode())
    return ans
'''