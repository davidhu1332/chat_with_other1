import socket
import threading
import time
import json
import os
import hashlib
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog

class LoginWindow:
    def __init__(self, parent, host, port, on_success):
        self.parent = parent
        self.host = host
        self.port = port
        self.on_success = on_success  # 登录成功后的回调函数
        self.client = None
        self.auth_result = None
        
        # 创建登录窗口
        self.window = Toplevel(parent)
        self.window.title("登录/注册")
        self.window.geometry("400x300")
        self.window.resizable(False, False)
        self.window.transient(parent)  # 设置为父窗口的模态窗口
        self.window.grab_set()  # 模态窗口
        
        # 窗口关闭事件
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        # 创建登录/注册界面
        self.create_widgets()
        
        # 尝试连接服务器
        self.status_label.config(text="正在连接服务器...")
        self.connect_thread = threading.Thread(target=self.connect_to_server)
        self.connect_thread.daemon = True
        self.connect_thread.start()
    
    def create_widgets(self):
        # 标签框架
        title_frame = Frame(self.window)
        title_frame.pack(fill=X, padx=20, pady=(20,10))
        
        # 标题
        Label(title_frame, text="用户登录", font=("宋体", 16, "bold")).pack()
        
        # 主框架
        main_frame = Frame(self.window)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        # 用户名
        Label(main_frame, text="用户名:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.username_entry = ttk.Entry(main_frame, width=30)
        self.username_entry.grid(row=0, column=1, sticky=W+E, padx=5, pady=5)
        
        # 密码
        Label(main_frame, text="密码:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.password_entry = ttk.Entry(main_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, sticky=W+E, padx=5, pady=5)
        
        # 服务器信息
        server_frame = Frame(main_frame)
        server_frame.grid(row=2, column=0, columnspan=2, sticky=W+E, padx=5, pady=5)
        self.server_label = Label(server_frame, text=f"服务器: {self.host}:{self.port}")
        self.server_label.pack(anchor=W)
        
        # 状态标签
        self.status_label = Label(main_frame, text="", fg="blue")
        self.status_label.grid(row=3, column=0, columnspan=2, sticky=W+E, padx=5, pady=5)
        
        # 按钮框架
        button_frame = Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, sticky=E, padx=5, pady=5)
        
        self.login_button = ttk.Button(button_frame, text="登录", command=self.login, state='disabled')
        self.login_button.pack(side=RIGHT, padx=5)
        
        self.register_button = ttk.Button(button_frame, text="注册", command=self.register, state='disabled')
        self.register_button.pack(side=RIGHT, padx=5)
        
        self.cancel_button = ttk.Button(button_frame, text="取消", command=self.cancel)
        self.cancel_button.pack(side=RIGHT, padx=5)
    
    def connect_to_server(self):
        """连接到服务器"""
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((self.host, self.port))
            
            # 接收服务器的认证请求
            auth_request = self.client.recv(1024).decode('utf-8')
            if auth_request == 'AUTH_REQUIRED':
                # 启用登录/注册按钮
                self.window.after(0, lambda: self.login_button.config(state='normal'))
                self.window.after(0, lambda: self.register_button.config(state='normal'))
                self.window.after(0, lambda: self.status_label.config(text="请登录或注册"))
                
                # 设置回车键登录
                self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())
                self.password_entry.bind("<Return>", lambda e: self.login())
                
                # 设置焦点
                self.username_entry.focus()
            else:
                # 服务器未请求认证
                self.window.after(0, lambda: self.status_label.config(text="服务器未要求认证，请检查服务器版本", fg="red"))
                self.window.after(2000, self.cancel)
        except Exception as e:
            # 连接失败
            error_msg = f"无法连接到服务器: {str(e)}"
            self.window.after(0, lambda: self.check_window_exists(error_msg))
            self.window.after(1000, self.cancel)
    
    def check_window_exists(self, error_msg):
        """检查窗口是否存在后更新UI"""
        try:
            if self.window.winfo_exists():
                self.status_label.config(text=error_msg, fg="red")
                messagebox.showerror("连接错误", error_msg, parent=self.window)
        except TclError:
            # 窗口已被销毁，忽略
            pass
            
    def login(self):
        """登录处理"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_label.config(text="用户名和密码不能为空", fg="red")
            return
        
        # 禁用按钮
        self.login_button.config(state='disabled')
        self.register_button.config(state='disabled')
        self.status_label.config(text="正在登录...", fg="blue")
        
        # 发送登录请求
        try:
            login_request = f"LOGIN:{username}:{hashlib.sha256(password.encode('utf-8')).hexdigest()}"
            self.client.send(login_request.encode('utf-8'))
            
            # 接收登录结果
            result = self.client.recv(1024).decode('utf-8')
            
            if result == "LOGIN_SUCCESS":
                # 登录成功
                self.status_label.config(text="登录成功，正在进入聊天室...", fg="green")
                
                # 回调父窗口，传递认证成功的客户端和用户名
                self.auth_result = {
                    "success": True,
                    "client": self.client,
                    "username": username
                }
                self.window.after(1000, self.window.destroy)
            elif result.startswith("LOGIN_FAILED:"):
                # 登录失败
                error_reason = result.split(":", 1)[1]
                self.status_label.config(text=f"登录失败: {error_reason}", fg="red")
                self.login_button.config(state='normal')
                self.register_button.config(state='normal')
        except Exception as e:
            self.status_label.config(text=f"通信错误: {str(e)}", fg="red")
            self.login_button.config(state='normal')
            self.register_button.config(state='normal')
    
    def register(self):
        """注册处理"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_label.config(text="用户名和密码不能为空", fg="red")
            return
        
        if len(username) < 3 or len(password) < 3:
            self.status_label.config(text="用户名和密码长度不能少于3个字符", fg="red")
            return
        
        # 禁用按钮
        self.login_button.config(state='disabled')
        self.register_button.config(state='disabled')
        self.status_label.config(text="正在注册...", fg="blue")
        
        # 发送注册请求
        try:
            register_request = f"REGISTER:{username}:{hashlib.sha256(password.encode('utf-8')).hexdigest()}"
            self.client.send(register_request.encode('utf-8'))
            
            # 接收注册结果
            result = self.client.recv(1024).decode('utf-8')
            
            if result == "REGISTER_SUCCESS":
                # 注册成功，自动登录
                self.status_label.config(text="注册成功，正在登录...", fg="green")
                self.window.after(1000, self.login)
            elif result.startswith("REGISTER_FAILED:"):
                # 注册失败
                error_reason = result.split(":", 1)[1]
                self.status_label.config(text=f"注册失败: {error_reason}", fg="red")
                self.login_button.config(state='normal')
                self.register_button.config(state='normal')
        except Exception as e:
            self.status_label.config(text=f"通信错误: {str(e)}", fg="red")
            self.login_button.config(state='normal')
            self.register_button.config(state='normal')
    
    def cancel(self):
        """取消登录/注册"""
        try:
            if self.client:
                self.client.close()
        except:
            pass
        
        self.auth_result = {"success": False}
        self.window.destroy()

class ChatClient:
    def __init__(self, host='127.0.0.1', port=55555):
        self.host = host
        self.port = port
        self.username = ""  # 从昵称改为用户名
        self.client = None
        self.connected = False
        self.message_history = []  # 存储消息历史
        self.max_history = 100  # 最大历史消息数量
        self.settings = self.load_settings()  # 加载设置
        self.is_admin = False  # 标记当前用户是否为管理员
        self.user_roles = {}  # 存储用户角色
        
        # 创建GUI
        self.root = Tk()
        self.root.title("聊天客户端")
        self.root.geometry("800x550")
        self.root.resizable(True, True)
        self.create_widgets()
        self.apply_settings()  # 应用加载的设置
    
    def create_widgets(self):
        # 创建菜单栏
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        # 文件菜单
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="连接服务器", command=self.connect_to_server)
        file_menu.add_command(label="断开连接", command=self.disconnect)
        file_menu.add_separator()
        file_menu.add_command(label="查看历史消息", command=self.show_message_history)
        file_menu.add_separator()
        file_menu.add_command(label="设置", command=self.show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.exit_app)
        
        # 管理菜单（初始时不显示，等待确认是否为管理员）
        self.admin_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="管理", menu=self.admin_menu)
        self.admin_menu.add_command(label="用户管理面板", command=self.show_admin_panel)
        
        # 初始时禁用管理菜单
        menubar.entryconfigure("管理", state="disabled")
        
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # 分割窗口
        pane = ttk.PanedWindow(main_frame, orient=HORIZONTAL)
        pane.pack(fill=BOTH, expand=True)
        
        # 左侧用户列表面板
        users_frame = ttk.LabelFrame(pane, text="用户列表")
        
        # 右侧消息面板
        message_frame = ttk.LabelFrame(pane, text="消息")
        
        pane.add(users_frame, weight=1)
        pane.add(message_frame, weight=3)
        
        # 用户列表
        self.users_listbox = Listbox(users_frame, height=20)
        self.users_listbox.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)
        users_scrollbar = ttk.Scrollbar(users_frame, orient=VERTICAL, command=self.users_listbox.yview)
        users_scrollbar.pack(side=RIGHT, fill=Y)
        self.users_listbox.config(yscrollcommand=users_scrollbar.set)
        
        # 绑定用户选择事件
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        # 消息区域
        self.message_area = scrolledtext.ScrolledText(message_frame, wrap=WORD, state='disabled')
        self.message_area.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # 消息类型选择
        message_type_frame = ttk.Frame(message_frame)
        message_type_frame.pack(fill=X, padx=5, pady=(0, 5))
        
        ttk.Label(message_type_frame, text="消息类型:").pack(side=LEFT, padx=(0, 5))
        
        self.message_type = StringVar(value="public")
        public_radio = ttk.Radiobutton(message_type_frame, text="公共消息", variable=self.message_type, value="public", command=self.on_message_type_change)
        public_radio.pack(side=LEFT, padx=5)
        
        private_radio = ttk.Radiobutton(message_type_frame, text="私聊", variable=self.message_type, value="private", command=self.on_message_type_change)
        private_radio.pack(side=LEFT, padx=5)
        
        # 私聊对象
        self.private_target_frame = ttk.Frame(message_type_frame)
        ttk.Label(self.private_target_frame, text="发送给:").pack(side=LEFT, padx=(5, 0))
        self.private_target = StringVar()
        self.private_target_label = ttk.Label(self.private_target_frame, textvariable=self.private_target)
        self.private_target_label.pack(side=LEFT, padx=5)
        
        # 初始隐藏私聊对象框架
        
        # 消息输入区域
        input_frame = ttk.Frame(message_frame)
        input_frame.pack(fill=X, padx=5, pady=(0, 5))
        
        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        send_button = ttk.Button(input_frame, text="发送", command=self.send_message)
        send_button.pack(side=RIGHT)
        
        # 状态栏
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=X, side=BOTTOM, padx=10, pady=5)
        
        self.connection_status = ttk.Label(status_frame, text="未连接")
        self.connection_status.pack(side=LEFT)
        
        self.server_info = ttk.Label(status_frame, text="")
        self.server_info.pack(side=RIGHT)
    
    def on_message_type_change(self):
        if self.message_type.get() == "private":
            self.private_target_frame.pack(side=LEFT, padx=5)
        else:
            self.private_target_frame.pack_forget()
    
    def on_user_select(self, event=None):
        if not self.connected:
            return
            
        selected = self.users_listbox.curselection()
        if selected:
            index = selected[0]
            user = self.users_listbox.get(index)
            if user != self.username:  # 不能给自己发私聊
                self.message_type.set("private")
                self.private_target.set(user)
                self.message_entry.focus()
            
    def connect_to_server(self):
        # 打开连接对话框
        connect_dialog = Toplevel(self.root)
        connect_dialog.title("连接到服务器")
        connect_dialog.geometry("300x150")
        connect_dialog.transient(self.root)
        connect_dialog.grab_set()
        
        # 服务器地址和端口输入框
        ttk.Label(connect_dialog, text="服务器地址:").grid(row=0, column=0, padx=10, pady=10, sticky=W)
        host_var = StringVar(value=self.host)
        host_entry = ttk.Entry(connect_dialog, textvariable=host_var, width=20)
        host_entry.grid(row=0, column=1, padx=10, pady=10, sticky=(W, E))
        
        ttk.Label(connect_dialog, text="端口:").grid(row=1, column=0, padx=10, pady=10, sticky=W)
        port_var = StringVar(value=str(self.port))
        port_entry = ttk.Entry(connect_dialog, textvariable=port_var, width=20)
        port_entry.grid(row=1, column=1, padx=10, pady=10, sticky=(W, E))
        
        # 按钮
        btn_frame = ttk.Frame(connect_dialog)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        def connect_action():
            host = host_var.get()
            try:
                port = int(port_var.get())
            except ValueError:
                messagebox.showerror("错误", "端口必须是一个数字!", parent=connect_dialog)
                return
            
            # 保存设置
            self.host = host
            self.port = port
            self.settings['host'] = host
            self.settings['port'] = port
            self.save_current_settings()
            
            # 关闭对话框
            connect_dialog.destroy()
            
            # 执行连接
            self.do_connect()
        
        ttk.Button(btn_frame, text="连接", command=connect_action).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=connect_dialog.destroy).pack(side=LEFT, padx=5)
        
        # 设置回车键连接
        host_entry.bind("<Return>", lambda e: port_entry.focus())
        port_entry.bind("<Return>", lambda e: connect_action())
        
        # 设置初始焦点
        host_entry.focus()
    
    def request_user_list(self):
        if self.connected:
            try:
                self.client.send("/用户列表".encode('utf-8'))
                self.add_system_message("正在刷新用户列表...")
            except:
                self.disconnect()
    
    def disconnect(self):
        if self.connected:
            try:
                self.client.close()
            except:
                pass
                
            self.connected = False
            
            # 更新状态
            self.connection_status.config(text="未连接")
            self.server_info.config(text="")
            
            # 清空用户列表
            self.users_listbox.delete(0, END)
            
            self.add_system_message("已断开与服务器的连接")
    
    def receive(self):
        while self.connected:
            try:
                message = self.client.recv(1024).decode('utf-8')
                
                if message:
                    # 处理不同类型的消息
                    if message.startswith("[系统消息]"):
                        # 系统消息
                        self.add_system_message(message[7:])
                        
                        # 检查是否包含管理员信息
                        if "您已被设置为管理员" in message or "您是管理员" in message:
                            self.is_admin = True
                            self.root.after(0, self.enable_admin_menu)
                        elif "您的管理员权限已被取消" in message or "您不是管理员" in message:
                            self.is_admin = False
                            self.root.after(0, self.disable_admin_menu)
                    
                    elif message.startswith("[用户列表]"):
                        # 用户列表
                        users = message[6:].split(",")
                        self.root.after(0, lambda u=users: self.update_user_list(u))
                        
                    elif message.startswith("USER_LIST:"):
                        try:
                            # 尝试解析JSON格式的用户列表
                            list_data = message[10:]
                            try:
                                # 尝试作为JSON解析
                                user_data = json.loads(list_data)
                                # 初始化用户角色字典
                                self.user_roles = {}
                                users = []
                                
                                # 提取用户名和角色信息
                                for user in user_data:
                                    username = user.get("username", "")
                                    is_admin = user.get("is_admin", False)
                                    is_muted = user.get("is_muted", False)
                                    
                                    if username:
                                        users.append(username)
                                        self.user_roles[username] = {
                                            "is_admin": is_admin,
                                            "is_muted": is_muted
                                        }
                                
                                # 更新用户列表
                                self.root.after(0, lambda u=users: self.update_user_list(u))
                            except json.JSONDecodeError:
                                # 如果不是JSON格式，按原来方式处理
                                users = list_data.split(",")
                                self.root.after(0, lambda u=users: self.update_user_list(u))
                        except Exception as e:
                            # 如果处理失败，回退到简单格式
                            users = message[10:].split(",")
                            self.root.after(0, lambda u=users: self.update_user_list(u))
                    
                    elif message.startswith("[私信 from"):
                        # 接收到的私聊消息
                        sender = message[message.find("from ")+5:message.find("]")]
                        content = message[message.find("] ")+2:]
                        self.add_private_message(sender, content)
                    
                    elif message.startswith("[私信 to"):
                        # 发出去的私聊消息确认
                        recipient = message[message.find("to ")+3:message.find("]")]
                        content = message[message.find("] ")+2:]
                        self.add_outgoing_private_message(recipient, content)
                    
                    elif message.startswith("[服务器公告]"):
                        # 服务器公告
                        self.add_system_message(message)
                        
                    elif message.startswith("[管理员帮助]") or (message.startswith("[帮助]") and "管理员命令" in message):
                        # 包含管理员命令的帮助信息，说明是管理员
                        self.is_admin = True
                        self.root.after(0, self.enable_admin_menu)
                    
                    else:
                        # 普通消息
                        self.add_message("", message)
                        
                        # 检查登录成功后的管理员确认
                        if "欢迎加入聊天室" in message:
                            # 检查管理员状态
                            self.root.after(1000, self.check_admin_status)
            except Exception as ex:
                if self.connected:
                    print(f"接收消息出错: {str(ex)}")
                    self.connected = False
                    
                    # 保存错误信息到局部变量，避免在lambda中直接引用ex
                    error_msg = str(ex)
                    self.root.after(0, lambda: self.connection_status.config(text="连接已断开"))
                    self.root.after(0, lambda: self.add_system_message("与服务器的连接已断开"))
                    self.root.after(0, lambda msg=error_msg: self.add_system_message(f"错误信息: {msg}"))
                break
    
    def update_user_list(self, users):
        """更新GUI中的用户列表"""
        # 清空用户列表
        self.users_listbox.delete(0, END)
        
        # 排序用户列表（自己始终显示在最上方）
        sorted_users = sorted([user for user in users if user != self.username])
        if self.username in users:
            sorted_users.insert(0, self.username)
        
        # 移除自己的昵称用于私聊选择
        private_users = [user for user in sorted_users if user != self.username]
        
        # 检查是否存在private_target_combo属性再更新
        if hasattr(self, 'private_target_combo') and self.private_target_combo is not None:
            self.private_target_combo['values'] = private_users
        
        # 如果当前选中的私聊对象不在列表中，重置私聊设置
        if self.message_type.get() == "private":
            target = self.private_target.get()
            if target and target not in private_users:
                self.add_system_message(f"用户 {target} 已离线，私聊已取消")
                self.message_type.set("public")
                self.private_target.set("")
        
        # 添加所有用户到列表框（包括自己）
        for user in sorted_users:
            if user == self.username:
                self.users_listbox.insert(END, f"{user} (你)")
            else:
                self.users_listbox.insert(END, user)
        
        # 显示用户总数
        total_users = len(users)
        self.add_system_message(f"当前在线用户: {total_users}人")
    
    def send_message(self, event=None):
        if self.connected:
            message = self.message_entry.get()
            if message:
                try:
                    if self.message_type.get() == "private":
                        target = self.private_target.get()
                        if target:
                            # 发送私聊消息格式: /私聊 目标昵称 消息内容
                            self.client.send(f"/私聊 {target} {message}".encode('utf-8'))
                        else:
                            messagebox.showinfo("提示", "请选择私聊对象")
                    else:
                        # 发送公共消息
                        self.client.send(message.encode('utf-8'))
                    
                    self.message_entry.delete(0, END)
                except:
                    self.add_system_message("消息发送失败!")
                    self.disconnect()
        return 'break'  # 防止事件继续传播
    
    def add_message(self, sender, message):
        # 获取当前时间
        current_time = time.strftime("%H:%M:%S", time.localtime())
        
        formatted_message = f"[{current_time}] {sender}: {message}"
        
        self.message_area.config(state='normal')
        self.message_area.insert(END, f"{formatted_message}\n")
        self.message_area.see(END)
        self.message_area.config(state='disabled')
        
        # 添加到历史记录
        self.message_history.append(formatted_message)
        if len(self.message_history) > self.max_history:
            self.message_history.pop(0)
    
    def add_private_message(self, sender, message):
        # 私聊消息特殊标记
        current_time = time.strftime("%H:%M:%S", time.localtime())
        formatted_message = f"[{current_time}] [私聊] {sender}: {message}"
        
        self.message_area.config(state='normal')
        
        # 插入标签开始
        self.message_area.insert(END, formatted_message + "\n", "private")
        self.message_area.tag_configure("private", foreground="purple")
        
        self.message_area.see(END)
        self.message_area.config(state='disabled')
        
        # 添加到历史记录
        self.message_history.append(formatted_message)
        if len(self.message_history) > self.max_history:
            self.message_history.pop(0)
    
    def add_outgoing_private_message(self, target, message):
        # 发出的私聊消息特殊标记
        current_time = time.strftime("%H:%M:%S", time.localtime())
        formatted_message = f"[{current_time}] [发送给 {target}]: {message}"
        
        self.message_area.config(state='normal')
        
        # 使用标签设置颜色
        self.message_area.insert(END, formatted_message + "\n", "outgoing_private")
        self.message_area.tag_configure("outgoing_private", foreground="blue")
        
        self.message_area.see(END)
        self.message_area.config(state='disabled')
        
        # 添加到历史记录
        self.message_history.append(formatted_message)
        if len(self.message_history) > self.max_history:
            self.message_history.pop(0)
        
    def add_system_message(self, message):
        # 系统消息特殊标记
        current_time = time.strftime("%H:%M:%S", time.localtime())
        formatted_message = f"[{current_time}] [系统] {message}"
        
        self.message_area.config(state='normal')
        
        # 使用标签设置颜色
        self.message_area.insert(END, formatted_message + "\n", "system")
        self.message_area.tag_configure("system", foreground="green")
        
        self.message_area.see(END)
        self.message_area.config(state='disabled')
        
        # 添加到历史记录
        self.message_history.append(formatted_message)
        if len(self.message_history) > self.max_history:
            self.message_history.pop(0)
            
    def show_message_history(self):
        # 显示消息历史记录
        history_window = Toplevel(self.root)
        history_window.title("消息历史")
        history_window.geometry("600x400")
        
        # 历史消息区域
        history_area = scrolledtext.ScrolledText(history_window, wrap=WORD)
        history_area.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # 显示历史消息
        for message in self.message_history:
            # 根据消息类型设置颜色
            if "[私聊]" in message:
                history_area.insert(END, f"{message}\n", "private")
                history_area.tag_configure("private", foreground="purple")
            elif "[发送给" in message:
                history_area.insert(END, f"{message}\n", "outgoing")
                history_area.tag_configure("outgoing", foreground="blue")
            elif "系统" in message or "[服务器公告]" in message:
                history_area.insert(END, f"{message}\n", "system")
                history_area.tag_configure("system", foreground="green")
            else:
                history_area.insert(END, f"{message}\n")
        
        # 按钮框架
        button_frame = ttk.Frame(history_window)
        button_frame.pack(fill=X, padx=10, pady=5)
        
        # 保存按钮
        save_button = ttk.Button(button_frame, text="保存历史记录", 
                               command=lambda: self.save_history_to_file(history_area.get("1.0", END)))
        save_button.pack(side=LEFT, padx=5)
        
        # 清空按钮
        clear_button = ttk.Button(button_frame, text="清空历史记录", 
                                command=lambda: self.clear_history(history_area))
        clear_button.pack(side=LEFT, padx=5)
        
        # 关闭按钮
        close_button = ttk.Button(button_frame, text="关闭", command=history_window.destroy)
        close_button.pack(side=RIGHT, padx=5)
    
    def save_history_to_file(self, history_text):
        # 保存历史记录到文件
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="保存历史记录"
        )
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(history_text)
                messagebox.showinfo("成功", "历史记录已保存")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {str(e)}")
    
    def clear_history(self, history_area=None):
        # 清空历史记录
        if messagebox.askyesno("确认", "确定要清空历史记录吗?"):
            self.message_history = []
            if history_area:
                history_area.delete("1.0", END)
            messagebox.showinfo("成功", "历史记录已清空")
    
    def show_settings(self):
        # 显示设置对话框
        settings_window = Toplevel(self.root)
        settings_window.title("客户端设置")
        settings_window.geometry("400x300")
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # 设置框架
        settings_frame = ttk.Frame(settings_window, padding=10)
        settings_frame.pack(fill=BOTH, expand=True)
        
        # 默认服务器设置
        ttk.Label(settings_frame, text="默认服务器:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        host_var = StringVar(value=self.host)
        host_entry = ttk.Entry(settings_frame, textvariable=host_var)
        host_entry.grid(row=0, column=1, sticky=(W, E), padx=5, pady=5)
        
        # 默认端口设置
        ttk.Label(settings_frame, text="默认端口:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        port_var = IntVar(value=self.port)
        port_entry = ttk.Entry(settings_frame, textvariable=port_var)
        port_entry.grid(row=1, column=1, sticky=(W, E), padx=5, pady=5)
        
        # 最大历史记录设置
        ttk.Label(settings_frame, text="最大历史记录数:").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        history_var = IntVar(value=self.max_history)
        history_entry = ttk.Entry(settings_frame, textvariable=history_var)
        history_entry.grid(row=2, column=1, sticky=(W, E), padx=5, pady=5)
        
        # 按钮框架
        button_frame = ttk.Frame(settings_window)
        button_frame.pack(fill=X, padx=10, pady=10)
        
        # 保存按钮
        save_button = ttk.Button(button_frame, text="保存", 
                               command=lambda: self.save_settings(host_var.get(), port_var.get(), history_var.get(), settings_window))
        save_button.pack(side=LEFT, padx=5)
        
        # 取消按钮
        cancel_button = ttk.Button(button_frame, text="取消", command=settings_window.destroy)
        cancel_button.pack(side=RIGHT, padx=5)
    
    def save_settings(self, host, port, max_history, window):
        self.host = host
        self.port = port
        self.max_history = max_history
        
        # 保存设置到文件
        settings = {
            "host": self.host,
            "port": self.port,
            "max_history": self.max_history
        }
        
        try:
            with open("settings.json", "w") as f:
                json.dump(settings, f)
            window.destroy()
            messagebox.showinfo("成功", "设置已保存!")
        except Exception as e:
            messagebox.showerror("错误", f"无法保存设置: {str(e)}")
    
    def load_settings(self):
        # 从文件加载设置
        settings = {
            "host": "127.0.0.1",
            "port": 55555,
            "max_history": 100
        }
        
        try:
            if os.path.exists("settings.json"):
                with open("settings.json", "r") as f:
                    loaded_settings = json.load(f)
                    settings.update(loaded_settings)
        except Exception as e:
            print(f"加载设置时出错: {str(e)}")
        
        return settings
    
    def apply_settings(self):
        # 应用加载的设置
        self.host = self.settings.get("host", "127.0.0.1")
        self.port = self.settings.get("port", 55555)
        self.max_history = self.settings.get("max_history", 100)
        
    def exit_app(self):
        if messagebox.askokcancel("退出", "确定要退出吗?"):
            if self.connected:
                try:
                    self.client.close()
                except:
                    pass
            self.root.destroy()
            
    def run(self):
        # 启动主循环
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
        self.root.mainloop()

    def save_current_settings(self):
        """保存当前客户端设置"""
        # 保存设置到文件
        settings = {
            "host": self.host,
            "port": self.port,
            "max_history": self.max_history
        }
        
        try:
            with open("settings.json", "w") as f:
                json.dump(settings, f)
        except Exception as e:
            messagebox.showerror("错误", f"无法保存设置: {str(e)}")

    def show_admin_panel(self):
        """显示管理员控制面板"""
        if not self.is_admin:
            messagebox.showinfo("提示", "您不是管理员，无法访问此功能")
            return
        
        # 创建管理面板窗口
        admin_window = Toplevel(self.root)
        admin_window.title("管理员控制面板")
        admin_window.geometry("700x500")
        admin_window.transient(self.root)  # 设置为主窗口的子窗口
        
        # 创建选项卡控件
        notebook = ttk.Notebook(admin_window)
        notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # 用户管理选项卡
        user_tab = ttk.Frame(notebook)
        notebook.add(user_tab, text="用户管理")
        
        # 广播消息选项卡
        broadcast_tab = ttk.Frame(notebook)
        notebook.add(broadcast_tab, text="消息广播")
        
        # 活动日志选项卡
        log_tab = ttk.Frame(notebook)
        notebook.add(log_tab, text="活动日志")
        
        # ============= 用户管理选项卡内容 =============
        user_frame = ttk.LabelFrame(user_tab, text="用户列表")
        user_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # 创建用户树状视图
        columns = ('用户名', '状态', '权限')
        user_tree = ttk.Treeview(user_frame, columns=columns, show='headings')
        
        # 设置列标题
        for col in columns:
            user_tree.heading(col, text=col)
        
        user_tree.column('用户名', width=150)
        user_tree.column('状态', width=100)
        user_tree.column('权限', width=100)
        
        user_tree.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(user_frame, orient=VERTICAL, command=user_tree.yview)
        user_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # 绑定双击事件
        user_tree.bind("<Double-1>", lambda event: self.show_user_actions(event, user_tree, admin_window))
        
        # 按钮框架
        buttons_frame = ttk.Frame(user_frame)
        buttons_frame.pack(fill=X, side=BOTTOM, padx=5, pady=5)
        
        # 刷新用户按钮
        refresh_button = ttk.Button(buttons_frame, text="刷新用户列表", 
                                  command=lambda: self.refresh_user_tree(user_tree))
        refresh_button.pack(side=LEFT, padx=5, pady=5)
        
        # 禁言用户按钮
        mute_button = ttk.Button(buttons_frame, text="禁言用户", 
                               command=lambda: self.mute_selected_user(user_tree, admin_window))
        mute_button.pack(side=LEFT, padx=5, pady=5)
        
        # 解除禁言按钮
        unmute_button = ttk.Button(buttons_frame, text="解除禁言", 
                                 command=lambda: self.unmute_selected_user(user_tree, admin_window))
        unmute_button.pack(side=LEFT, padx=5, pady=5)
        
        # 踢出用户按钮
        kick_button = ttk.Button(buttons_frame, text="踢出用户", 
                               command=lambda: self.kick_selected_user(user_tree, admin_window))
        kick_button.pack(side=LEFT, padx=5, pady=5)
        
        # 初始化用户列表
        self.refresh_user_tree(user_tree)
        
        # ============= 广播消息选项卡内容 =============
        broadcast_frame = ttk.LabelFrame(broadcast_tab, text="发送广播消息")
        broadcast_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # 消息类型选择
        type_frame = ttk.Frame(broadcast_frame)
        type_frame.pack(fill=X, padx=5, pady=5)
        
        ttk.Label(type_frame, text="消息类型:").pack(side=LEFT, padx=5)
        
        message_type = StringVar(value="normal")
        ttk.Radiobutton(type_frame, text="普通消息", variable=message_type, value="normal").pack(side=LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="警告消息", variable=message_type, value="warning").pack(side=LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="通知消息", variable=message_type, value="notification").pack(side=LEFT, padx=5)
        
        # 预设消息选择
        preset_frame = ttk.Frame(broadcast_frame)
        preset_frame.pack(fill=X, padx=5, pady=5)
        
        ttk.Label(preset_frame, text="预设消息:").pack(side=LEFT, padx=5)
        
        preset_messages = ["服务器将在5分钟后维护", "欢迎使用聊天系统", "请遵守聊天规则", "系统升级完成"]
        preset_combo = ttk.Combobox(preset_frame, values=preset_messages, width=40)
        preset_combo.pack(side=LEFT, padx=5, expand=True, fill=X)
        
        # 插入按钮
        insert_button = ttk.Button(preset_frame, text="插入", 
                                 command=lambda: broadcast_text.insert(END, preset_combo.get()))
        insert_button.pack(side=LEFT, padx=5)
        
        # 消息内容
        ttk.Label(broadcast_frame, text="消息内容:").pack(anchor=W, padx=10, pady=(10,5))
        
        broadcast_text = Text(broadcast_frame, height=10, wrap=WORD)
        broadcast_text.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # 发送按钮
        send_frame = ttk.Frame(broadcast_frame)
        send_frame.pack(fill=X, padx=10, pady=10)
        
        send_button = ttk.Button(send_frame, text="发送广播", 
                               command=lambda: self.send_broadcast(broadcast_text.get("1.0", END).strip(), 
                                                                message_type.get()))
        send_button.pack(side=RIGHT, padx=5)
        
        clear_button = ttk.Button(send_frame, text="清空", 
                                command=lambda: broadcast_text.delete("1.0", END))
        clear_button.pack(side=RIGHT, padx=5)
        
        # ============= 活动日志选项卡内容 =============
        log_frame = ttk.LabelFrame(log_tab, text="系统日志")
        log_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # 日志显示区域
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=WORD, height=15)
        self.log_area.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.log_area.insert(END, "=== 系统日志 ===\n")
        
        # 日志操作按钮
        log_btn_frame = ttk.Frame(log_frame)
        log_btn_frame.pack(fill=X, padx=5, pady=5)
        
        refresh_log_btn = ttk.Button(log_btn_frame, text="刷新日志", 
                                   command=lambda: self.request_logs())
        refresh_log_btn.pack(side=LEFT, padx=5)
        
        clear_log_btn = ttk.Button(log_btn_frame, text="清空日志", 
                                 command=lambda: self.log_area.delete("1.0", END))
        clear_log_btn.pack(side=LEFT, padx=5)
        
        export_log_btn = ttk.Button(log_btn_frame, text="导出日志", 
                                  command=lambda: self.export_logs())
        export_log_btn.pack(side=LEFT, padx=5)
        
        # 底部按钮
        close_button = ttk.Button(admin_window, text="关闭", command=admin_window.destroy)
        close_button.pack(side=BOTTOM, padx=10, pady=10)
    
    def refresh_user_tree(self, tree):
        """刷新用户树状图"""
        # 清空树
        for item in tree.get_children():
            tree.delete(item)
        
        if self.connected:
            # 向服务器请求最新用户列表
            try:
                # 发送用户列表请求，使用特定请求来获取包含角色信息的用户列表
                self.client.send("/用户列表_详细".encode('utf-8'))
                
                # 等待服务器响应以获取最新的用户角色信息
                # 在 receive 方法中会接收并更新 self.user_roles
                # 为避免界面阻塞，设置一个短暂延迟，让服务器响应有时间处理
                time.sleep(0.3)
                
                # 添加现有用户
                for user in self.users_listbox.get(0, END):
                    username = user
                    if "(你)" in username:
                        username = username.replace(" (你)", "")
                    
                    status = "在线"
                    perm = "普通用户"  # 默认值
                    
                    # 先从用户角色字典中查找用户状态
                    if hasattr(self, 'user_roles') and username in self.user_roles:
                        if self.user_roles[username]["is_admin"]:
                            perm = "管理员"
                        if self.user_roles[username]["is_muted"]:
                            status = "已禁言"
                    # 如果是自己且是管理员，确保显示正确
                    elif username == self.username and self.is_admin:
                        perm = "管理员"
                    
                    tree.insert('', END, values=(username, status, perm))
            except Exception as e:
                messagebox.showerror("错误", f"刷新用户列表失败: {str(e)}")
    
    def send_broadcast(self, message, message_type):
        """发送广播消息"""
        if not message:
            messagebox.showinfo("提示", "消息内容不能为空")
            return
        
        if self.connected and self.is_admin:
            try:
                if message_type == "warning":
                    self.client.send(f"/广播警告 {message}".encode('utf-8'))
                elif message_type == "notification":
                    self.client.send(f"/广播通知 {message}".encode('utf-8'))
                else:
                    self.client.send(f"/广播 {message}".encode('utf-8'))
                
                self.add_system_message(f"已发送广播消息")
                messagebox.showinfo("成功", "广播消息已发送")
            except Exception as e:
                messagebox.showerror("错误", f"发送广播失败: {str(e)}")
    
    def request_logs(self):
        """请求系统日志"""
        if self.connected and self.is_admin:
            try:
                self.client.send("/系统日志".encode('utf-8'))
                self.add_system_message("已请求系统日志")
            except Exception as e:
                messagebox.showerror("错误", f"请求日志失败: {str(e)}")
    
    def export_logs(self):
        """导出系统日志"""
        if not hasattr(self, 'log_area'):
            messagebox.showinfo("提示", "没有可导出的日志")
            return
            
        log_content = self.log_area.get("1.0", END)
        if not log_content.strip():
            messagebox.showinfo("提示", "日志内容为空")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="导出日志"
        )
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(log_content)
                messagebox.showinfo("成功", "日志已导出")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")
    
    def show_user_actions(self, event, tree, parent_window):
        """显示用户操作菜单"""
        # 获取选择的用户
        item = tree.selection()[0]
        user_info = tree.item(item, "values")
        username = user_info[0]
        
        # 从用户名中移除"(你)"后缀
        if "(你)" in username:
            username = username.replace(" (你)", "")
        
        # 防止对自己操作
        if username == self.username:
            messagebox.showinfo("提示", "不能对自己执行管理操作", parent=parent_window)
            return
        
        # 创建操作窗口
        action_window = Toplevel(parent_window)
        action_window.title(f"管理用户: {username}")
        action_window.geometry("300x250")
        action_window.transient(parent_window)
        action_window.grab_set()
        
        # 添加说明标签
        ttk.Label(action_window, text=f"对用户 {username} 执行操作:",
                 font=("黑体", 10)).pack(pady=(10,15), padx=20)
        
        # 创建操作按钮
        ttk.Button(action_window, text="禁言用户",
                  command=lambda: self.mute_user(username, action_window)).pack(fill=X, padx=20, pady=5)
        
        ttk.Button(action_window, text="解除禁言",
                  command=lambda: self.unmute_user(username, action_window)).pack(fill=X, padx=20, pady=5)
        
        ttk.Button(action_window, text="踢出用户",
                  command=lambda: self.kick_user(username, action_window)).pack(fill=X, padx=20, pady=5)
        
        ttk.Button(action_window, text="设置为管理员",
                  command=lambda: self.set_admin(username, action_window)).pack(fill=X, padx=20, pady=5)
        
        ttk.Button(action_window, text="取消管理员",
                  command=lambda: self.unset_admin(username, action_window)).pack(fill=X, padx=20, pady=5)
        
        ttk.Button(action_window, text="关闭",
                  command=action_window.destroy).pack(fill=X, padx=20, pady=(15,5))
    
    def mute_user(self, username, window=None):
        """禁言用户"""
        if self.connected and self.is_admin:
            try:
                self.client.send(f"/禁言 {username}".encode('utf-8'))
                if window:
                    window.destroy()
                self.add_system_message(f"已发送禁言 {username} 的请求")
                messagebox.showinfo("操作成功", f"已发送禁言 {username} 的请求")
            except Exception as e:
                messagebox.showerror("操作失败", f"禁言用户失败: {str(e)}")
    
    def unmute_user(self, username, window=None):
        """解除用户禁言"""
        if self.connected and self.is_admin:
            try:
                # 这里修改为服务器接受的命令格式
                self.client.send(f"/解除禁言 {username}".encode('utf-8'))
                if window:
                    window.destroy()
                self.add_system_message(f"已发送解除 {username} 禁言的请求")
                messagebox.showinfo("操作成功", f"已发送解除 {username} 禁言的请求")
            except Exception as e:
                messagebox.showerror("操作失败", f"解除禁言失败: {str(e)}")
    
    def kick_user(self, username, window=None):
        """踢出用户"""
        if self.connected and self.is_admin:
            try:
                self.client.send(f"/踢出 {username}".encode('utf-8'))
                if window:
                    window.destroy()
                self.add_system_message(f"已发送踢出 {username} 的请求")
                messagebox.showinfo("操作成功", f"已发送踢出 {username} 的请求")
            except Exception as e:
                messagebox.showerror("操作失败", f"踢出用户失败: {str(e)}")
    
    def set_admin(self, username, window=None):
        """设置用户为管理员"""
        if self.connected and self.is_admin:
            try:
                self.client.send(f"/设置管理员 {username}".encode('utf-8'))
                if window:
                    window.destroy()
                self.add_system_message(f"已发送设置 {username} 为管理员的请求")
                messagebox.showinfo("操作成功", f"已发送设置 {username} 为管理员的请求")
            except Exception as e:
                messagebox.showerror("操作失败", f"设置管理员失败: {str(e)}")
    
    def unset_admin(self, username, window=None):
        """取消用户的管理员权限"""
        if self.connected and self.is_admin:
            try:
                self.client.send(f"/取消管理员 {username}".encode('utf-8'))
                if window:
                    window.destroy()
                self.add_system_message(f"已发送取消 {username} 管理员权限的请求")
                messagebox.showinfo("操作成功", f"已发送取消 {username} 管理员权限的请求")
            except Exception as e:
                messagebox.showerror("操作失败", f"取消管理员失败: {str(e)}")
    
    def mute_selected_user(self, tree, parent_window):
        """禁言选中的用户"""
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个用户", parent=parent_window)
            return
            
        # 获取选择的用户
        item = selected[0]
        user_info = tree.item(item, "values")
        username = user_info[0]
        
        # 从用户名中移除"(你)"后缀
        if "(你)" in username:
            username = username.replace(" (你)", "")
        
        # 防止对自己操作
        if username == self.username:
            messagebox.showinfo("提示", "不能对自己执行管理操作", parent=parent_window)
            return
            
        # 禁言用户
        self.mute_user(username)
    
    def unmute_selected_user(self, tree, parent_window):
        """解除选中用户的禁言"""
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个用户", parent=parent_window)
            return
            
        # 获取选择的用户
        item = selected[0]
        user_info = tree.item(item, "values")
        username = user_info[0]
        
        # 从用户名中移除"(你)"后缀
        if "(你)" in username:
            username = username.replace(" (你)", "")
        
        # 防止对自己操作
        if username == self.username:
            messagebox.showinfo("提示", "不能对自己执行管理操作", parent=parent_window)
            return
            
        # 解除禁言
        self.unmute_user(username)
    
    def kick_selected_user(self, tree, parent_window):
        """踢出选中的用户"""
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个用户", parent=parent_window)
            return
            
        # 获取选择的用户
        item = selected[0]
        user_info = tree.item(item, "values")
        username = user_info[0]
        
        # 从用户名中移除"(你)"后缀
        if "(你)" in username:
            username = username.replace(" (你)", "")
        
        # 防止对自己操作
        if username == self.username:
            messagebox.showinfo("提示", "不能对自己执行管理操作", parent=parent_window)
            return
            
        # 踢出用户
        self.kick_user(username)
    
    def do_connect(self):
        """执行连接和登录流程"""
        login_window = LoginWindow(self.root, self.host, self.port, None)
        self.root.wait_window(login_window.window)
        
        # 检查登录结果
        if login_window.auth_result and login_window.auth_result.get("success"):
            # 获取认证成功的客户端和用户名
            self.client = login_window.auth_result.get("client")
            self.username = login_window.auth_result.get("username")
            self.connected = True
            
            # 更新界面
            self.connection_status.config(text=f"已连接: {self.username}")
            self.server_info.config(text=f"服务器: {self.host}:{self.port}")
            
            # 启动接收消息线程
            receive_thread = threading.Thread(target=self.receive)
            receive_thread.daemon = True
            receive_thread.start()
            
            # 显示系统欢迎消息
            self.add_system_message(f"已连接到聊天服务器")
            
            # 检查是否为管理员
            self.check_admin_status()
            
            # 立即请求用户列表
            self.request_user_list()
            
            return True
        else:
            messagebox.showinfo("连接失败", "未能连接到服务器或登录失败")
            return False

    def check_admin_status(self):
        """检查当前用户的管理员状态"""
        if self.connected:
            try:
                # 发送查询命令
                self.client.send("/我是管理员吗".encode('utf-8'))
                self.add_system_message("正在检查管理员权限...")
            except:
                pass

    def enable_admin_menu(self):
        """启用管理员菜单"""
        self.is_admin = True
        if hasattr(self, 'root') and hasattr(self.root, 'nametowidget'):
            menu = self.root.nametowidget(self.root.cget("menu"))
            try:
                menu.entryconfigure("管理", state="normal")
                self.add_system_message("管理员菜单已启用")
            except:
                print("启用管理员菜单失败")
    
    def disable_admin_menu(self):
        """禁用管理员菜单"""
        self.is_admin = False
        if hasattr(self, 'root') and hasattr(self.root, 'nametowidget'):
            menu = self.root.nametowidget(self.root.cget("menu"))
            try:
                menu.entryconfigure("管理", state="disabled")
            except:
                print("禁用管理员菜单失败")

if __name__ == "__main__":
    client = ChatClient()
    client.run()
