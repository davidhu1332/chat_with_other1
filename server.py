import socket
import threading
import time
import json
import os
import datetime
import hashlib
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog

# 获取本机IP地址的函数
def get_local_ip():
    try:
        # 创建一个临时socket连接到一个公共地址，这样可以获取本机在网络上的IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # 如果上面的方法失败，尝试获取主机名对应的IP
        try:
            host_name = socket.gethostname()
            ip = socket.gethostbyname(host_name)
            return ip
        except Exception:
            return "127.0.0.1"  # 如果都失败，返回本地回环地址

class ChatServer:
    def __init__(self, host='0.0.0.0', port=55555):
        self.host = host
        self.port = port
        self.server = None
        self.clients = []
        self.nicknames = []
        self.user_auth = {}  # 存储用户认证信息 {nickname: {"client": client, "is_logged_in": True}}
        self.muted_users = set()  # 被禁言的用户
        self.running = False
        self.message_history = []  # 存储消息历史
        self.max_history = 100  # 最大历史消息数量

        # 加载用户数据
        self.users_data = self.load_users_data()

        # 加载设置
        self.settings = self.load_settings()

        # 应用加载的设置
        self.apply_settings()  # 应用加载的设置

        # 创建GUI
        self.root = Tk()
        self.root.title("聊天服务器")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        self.create_widgets()

    def create_widgets(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)

        # 分割窗口
        pane = ttk.PanedWindow(main_frame, orient=HORIZONTAL)
        pane.pack(fill=BOTH, expand=True)

        # 左侧控制面板
        control_frame = ttk.LabelFrame(pane, text="服务器控制")

        # 右侧消息框
        message_frame = ttk.LabelFrame(pane, text="服务器消息")

        pane.add(control_frame, weight=1)
        pane.add(message_frame, weight=2)

        # 添加消息区域
        self.message_area = scrolledtext.ScrolledText(message_frame, wrap=WORD, state='disabled')
        self.message_area.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # 控制面板内容
        # 地址输入
        ttk.Label(control_frame, text="监听地址:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        self.host_entry = ttk.Entry(control_frame)
        self.host_entry.insert(0, self.settings['host'])
        self.host_entry.grid(row=0, column=1, sticky=W+E, padx=5, pady=5)

        # 端口输入
        ttk.Label(control_frame, text="端口:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        self.port_entry = ttk.Entry(control_frame)
        self.port_entry.insert(0, str(self.settings['port']))
        self.port_entry.grid(row=1, column=1, sticky=W+E, padx=5, pady=5)

        # 启动/停止按钮
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=2, column=0, columnspan=2, sticky=E+W, padx=5, pady=5)

        self.start_button = ttk.Button(button_frame, text="启动服务器", command=self.start_server)
        self.start_button.pack(side=LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="停止服务器", command=self.stop_server, state='disabled')
        self.stop_button.pack(side=LEFT, padx=5)

        # 用户管理按钮
        self.user_management_button = ttk.Button(button_frame, text="用户管理", command=self.manage_users)
        self.user_management_button.pack(side=LEFT, padx=5)

        # 状态标签
        self.status_label = ttk.Label(control_frame, text="状态: 已停止")
        self.status_label.grid(row=3, column=0, columnspan=2, sticky=W, padx=5, pady=5)

        # 连接客户端数量
        self.clients_label = ttk.Label(control_frame, text="已连接客户端: 0")
        self.clients_label.grid(row=4, column=0, columnspan=2, sticky=W, padx=5, pady=5)

        # 用户列表
        ttk.Label(control_frame, text="在线用户:").grid(row=5, column=0, sticky=W, padx=5, pady=5)

        users_frame = ttk.Frame(control_frame)
        users_frame.grid(row=6, column=0, columnspan=2, sticky=N+S+E+W, padx=5, pady=0)

        self.users_listbox = Listbox(users_frame, height=10)
        self.users_listbox.pack(side=LEFT, fill=BOTH, expand=True)

        users_scrollbar = ttk.Scrollbar(users_frame, orient=VERTICAL, command=self.users_listbox.yview)
        users_scrollbar.pack(side=RIGHT, fill=Y)
        self.users_listbox.config(yscrollcommand=users_scrollbar.set)

        # 用户操作按钮
        user_actions_frame = ttk.Frame(control_frame)
        user_actions_frame.grid(row=7, column=0, columnspan=2, sticky=E+W, padx=5, pady=5)

        kick_button = ttk.Button(user_actions_frame, text="踢出用户", command=self.kick_user_gui)
        kick_button.pack(side=LEFT, padx=5)

        message_button = ttk.Button(user_actions_frame, text="发送私信", command=self.message_user)
        message_button.pack(side=LEFT, padx=5)

    def kick_user_gui(self):
        """从GUI踢出选中的用户"""
        # 踢出选中的用户
        selected = self.users_listbox.curselection()
        if selected:
            index = selected[0]
            if index < len(self.nicknames):
                nickname = self.nicknames[index]
                client = self.clients[index]

                # 踢出用户
                self.kick_user_by_name("服务器", nickname)
        else:
            messagebox.showinfo("提示", "请先选择要踢出的用户")

    def message_user(self):
        """向选中的用户发送私信"""
        # 向选中的用户发送私信
        selected = self.users_listbox.curselection()
        if selected:
            index = selected[0]
            if index < len(self.nicknames):
                nickname = self.nicknames[index]
                message = simpledialog.askstring("私信", f"输入要发送给 {nickname} 的私信:", parent=self.root)

                if message:
                    self.send_private_message("服务器", nickname, message)
        else:
            messagebox.showinfo("提示", "请先选择要私信的用户")

    def start_server(self):
        if not self.running:
            host = self.host_entry.get()
            try:
                port = int(self.port_entry.get())
            except ValueError:
                messagebox.showerror("错误", "端口必须是一个数字!")
                return

            # 更新设置
            self.host = host
            self.port = port

            # 保存设置
            self.save_current_settings()

            # 创建socket
            try:
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.bind((host, port))
                self.server.listen()

                # 启动接收线程
                self.running = True
                self.receive_thread = threading.Thread(target=self.receive)
                self.receive_thread.daemon = True
                self.receive_thread.start()

                # 获取并显示本机IP地址
                local_ip = get_local_ip()
                self.log_message(f"服务器正在运行 - 本地IP: {local_ip}, 端口: {port}")
                self.log_message(f"其他设备可通过 {local_ip}:{port} 连接到此服务器")

                # 更新状态
                self.status_label.config(text=f"状态: 运行中 ({host}:{port})")
                self.start_button.config(state='disabled')
                self.stop_button.config(state='normal')

                # 禁用配置输入
                self.host_entry.config(state='disabled')
                self.port_entry.config(state='disabled')

            except Exception as e:
                messagebox.showerror("启动错误", f"无法启动服务器: {str(e)}")

    def stop_server(self):
        if self.running:
            # 向所有客户端发送服务器关闭消息
            self.broadcast("[服务器公告] 服务器即将关闭，感谢您的使用!".encode('utf-8'))

            # 关闭所有客户端连接
            for client in self.clients:
                try:
                    client.close()
                except:
                    pass

            # 停止服务器
            self.running = False
            try:
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.connect((self.host, self.port))  # 触发accept超时
                temp_socket.close()
            except:
                pass

            try:
                self.server.close()
            except:
                pass

            # 清空客户端列表
            self.clients = []
            self.nicknames = []
            self.user_auth = {}

            # 更新状态
            self.status_label.config(text="状态: 已停止")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')

            # 启用配置输入
            self.host_entry.config(state='normal')
            self.port_entry.config(state='normal')

            self.log_message("服务器已停止")

    def log_message(self, message):
        # 获取当前时间
        current_time = time.strftime("%H:%M:%S", time.localtime())
        formatted_message = f"[{current_time}] {message}"

        # 向消息区域添加消息
        self.message_area.config(state='normal')
        self.message_area.insert(END, f"{formatted_message}\n")
        self.message_area.see(END)
        self.message_area.config(state='disabled')

        # 添加到历史记录
        self.message_history.append(formatted_message)
        if len(self.message_history) > self.max_history:
            self.message_history.pop(0)

    def broadcast(self, message, exclude_client=None):
        # 向所有客户端发送消息
        for client in self.clients:
            if client != exclude_client:
                try:
                    client.send(message)
                except:
                    # 如果无法发送，移除客户端
                    self.remove_client(client)

    def remove_client(self, client):
        if client in self.clients:
            index = self.clients.index(client)
            nickname = self.nicknames[index]
            self.clients.remove(client)
            self.nicknames.remove(nickname)
            client.close()
            self.log_message(f"{nickname} 已断开连接!")
            self.clients_label.config(text=f"已连接客户端: {len(self.clients)}")
            self.update_user_list()
            self.broadcast(f"{nickname} 已离开聊天!".encode('utf-8'))

            # 广播更新后的用户列表
            self.broadcast_user_list()

    def handle(self, client):
        # 处理单个客户端的消息
        index = self.clients.index(client)
        nickname = self.nicknames[index]

        # 添加短暂延迟，确保客户端完成之前的通信
        time.sleep(0.3)

        # 发送欢迎消息
        client.send("欢迎加入聊天室!".encode('utf-8'))

        while True and self.running:
            try:
                message = client.recv(1024)
                if message:
                    # 检查是否是命令
                    decoded = message.decode('utf-8')

                    # 检查用户是否被禁言
                    if nickname in self.users_data['users'] and self.users_data['users'][nickname].get('is_muted', False) and not decoded.startswith('/'):
                        client.send("错误: 您已被禁言，无法发送消息".encode('utf-8'))
                        continue

                    if decoded == "/用户列表":
                        # 发送用户列表
                        self.send_user_list(client)
                    elif decoded == "/用户列表_详细":
                        # 发送详细用户列表（仅包含JSON格式，不发送简单格式）
                        self.send_detailed_user_list(client)
                    elif decoded.startswith("/私聊 "):
                        # 格式: /私聊 用户名 消息内容
                        parts = decoded[4:].split(" ", 1)
                        if len(parts) == 2:
                            target_nick, private_msg = parts
                            self.send_private_message(nickname, target_nick, private_msg)
                        else:
                            client.send("格式错误! 使用: /私聊 用户名 消息内容".encode('utf-8'))
                    elif decoded.startswith("/禁言 ") and self.users_data['users'][nickname].get('is_admin', False):
                        # 格式: /禁言 用户名
                        parts = decoded[4:].split()
                        if len(parts) == 1:
                            target_nick = parts[0]
                            self.mute_user(nickname, target_nick)
                        else:
                            client.send("格式错误! 使用: /禁言 用户名".encode('utf-8'))
                    elif decoded.startswith("/解除禁言 ") and self.users_data['users'][nickname].get('is_admin', False):
                        # 格式: /解除禁言 用户名
                        parts = decoded[5:].split()
                        if len(parts) == 1:
                            target_nick = parts[0]
                            self.unmute_user(nickname, target_nick)
                        else:
                            client.send("格式错误! 使用: /解除禁言 用户名".encode('utf-8'))
                    elif decoded.startswith("/踢出 ") and self.users_data['users'][nickname].get('is_admin', False):
                        # 格式: /踢出 用户名
                        parts = decoded[4:].split()
                        if len(parts) == 1:
                            target_nick = parts[0]
                            self.kick_user_by_name(nickname, target_nick)
                        else:
                            client.send("格式错误! 使用: /踢出 用户名".encode('utf-8'))
                    elif decoded == "/帮助":
                        # 发送帮助信息
                        self.send_help_message(client, nickname)
                    elif decoded == "/我是管理员吗":
                        # 检查用户是否为管理员
                        if nickname in self.users_data['users'] and self.users_data['users'][nickname].get('is_admin', False):
                            client.send("[系统消息] 您是管理员".encode('utf-8'))
                        else:
                            client.send("[系统消息] 您不是管理员".encode('utf-8'))
                    elif decoded.startswith("/修改密码 "):
                        # 格式: /修改密码 旧密码_哈希值 新密码_哈希值
                        parts = decoded[6:].split()
                        if len(parts) == 2:
                            old_password_hash, new_password_hash = parts

                            # 检查旧密码是否正确
                            if self.users_data['users'][nickname]['password'] == old_password_hash:
                                # 更新密码
                                self.users_data['users'][nickname]['password'] = new_password_hash
                                self.save_users_data()
                                client.send("[系统消息] 密码修改成功".encode('utf-8'))
                                self.log_message(f"用户 {nickname} 成功修改了密码")
                            else:
                                client.send("[系统消息] 密码修改失败: 原密码不正确".encode('utf-8'))
                        else:
                            client.send("[系统消息] 密码修改失败: 格式错误".encode('utf-8'))
                    else:
                        # 公共消息
                        formatted_message = f"{nickname}: {decoded}"
                        self.log_message(formatted_message)
                        broadcast_message = formatted_message.encode('utf-8')
                        self.broadcast(broadcast_message)
            except:
                # 如果发生错误，关闭连接
                self.remove_client(client)
                break

    def send_help_message(self, client, nickname):
        """发送帮助信息"""
        help_msg = "可用命令:\n"
        help_msg += "/用户列表 - 获取当前在线用户列表\n"
        help_msg += "/用户列表_详细 - 获取包含用户角色的详细在线用户列表\n"
        help_msg += "/私聊 用户名 消息 - 发送私聊消息\n"
        help_msg += "/帮助 - 显示此帮助信息\n"
        help_msg += "/我是管理员吗 - 查询自己的管理员状态\n"

        # 管理员命令
        if self.users_data['users'][nickname].get('is_admin', False):
            help_msg += "\n管理员命令:\n"
            help_msg += "/禁言 用户名 - 禁止用户发言\n"
            help_msg += "/解除禁言 用户名 - 允许用户发言\n"
            help_msg += "/踢出 用户名 - 将用户踢出聊天室\n"

        client.send(help_msg.encode('utf-8'))

    def mute_user(self, admin_nick, target_nick):
        """管理员禁言用户"""
        if target_nick in self.users_data['users']:
            # 移除不能禁言管理员的限制，允许管理员禁言任何人包括其他管理员
            # if self.users_data['users'][target_nick].get('is_admin', False) and admin_nick != target_nick:
            #     # 不能禁言其他管理员
            #     self.send_message_to_user(admin_nick, f"错误: 不能禁言管理员")
            #     return

            # 更新内存中的禁言状态
            self.users_data['users'][target_nick]['is_muted'] = True

            # 更新用户数据文件
            self.save_users_data()

            self.broadcast(f"[服务器公告] 用户 {target_nick} 已被 {admin_nick} 禁言".encode('utf-8'))
            self.log_message(f"管理员 {admin_nick} 禁言了用户 {target_nick}")
        else:
            self.send_message_to_user(admin_nick, f"错误: 用户 {target_nick} 不存在或未在线")

    def unmute_user(self, admin_nick, target_nick):
        """管理员解除用户禁言"""
        if target_nick in self.users_data['users']:
            # 更新内存中的禁言状态
            self.users_data['users'][target_nick]['is_muted'] = False

            # 更新用户数据文件
            self.save_users_data()

            self.broadcast(f"[服务器公告] 用户 {target_nick} 已被 {admin_nick} 解除禁言".encode('utf-8'))
            self.log_message(f"管理员 {admin_nick} 解除了用户 {target_nick} 的禁言")
        else:
            self.send_message_to_user(admin_nick, f"错误: 用户 {target_nick} 不存在或未在线")

    def kick_user_by_name(self, admin_nick, target_nick):
        """管理员踢出用户"""
        if target_nick in self.nicknames:
            # 检查是否是管理员踢出管理员（非服务器操作）
            if admin_nick != "服务器" and target_nick in self.users_data['users'] and self.users_data['users'][target_nick].get('is_admin', False):
                # 不允许管理员踢出其他管理员
                self.send_message_to_user(admin_nick, f"错误: 不能踢出管理员")
                return

            index = self.nicknames.index(target_nick)
            client = self.clients[index]

            # 发送踢出消息
            try:
                client.send(f"[服务器公告] 您已被{'服务器' if admin_nick == '服务器' else '管理员 ' + admin_nick} 踢出聊天室".encode('utf-8'))
            except:
                pass

            # 移除客户端
            self.remove_client(client)
            self.log_message(f"用户 {target_nick} 被{'服务器' if admin_nick == '服务器' else '管理员 ' + admin_nick} 踢出")

            # 广播消息
            self.broadcast(f"[服务器公告] 用户 {target_nick} 已被{'服务器' if admin_nick == '服务器' else '管理员 ' + admin_nick} 踢出聊天室".encode('utf-8'))
        else:
            self.send_message_to_user(admin_nick, f"错误: 用户 {target_nick} 不存在或未在线")

    def send_message_to_user(self, nickname, message):
        """向特定用户发送系统消息"""
        if nickname in self.nicknames:
            idx = self.nicknames.index(nickname)
            client = self.clients[idx]
            try:
                client.send(f"[系统消息] {message}".encode('utf-8'))
            except:
                # 如果发送失败，客户端可能已断开连接
                pass
        else:
            self.log_message(f"错误: 无法向用户 {nickname} 发送消息，该用户不存在或未在线")

    def send_private_message(self, sender, recipient, message):
        """发送私信"""
        # 检查接收者是否存在
        if recipient in self.nicknames:
            idx = self.nicknames.index(recipient)
            client = self.clients[idx]
            try:
                # 发送给接收者
                client.send(f"[私信 from {sender}] {message}".encode('utf-8'))

                # 如果发送者不是服务器，也发送一条确认消息给发送者
                if sender != "服务器" and sender in self.nicknames:
                    sender_idx = self.nicknames.index(sender)
                    sender_client = self.clients[sender_idx]
                    try:
                        sender_client.send(f"[私信 to {recipient}] {message}".encode('utf-8'))
                    except:
                        pass

                # 记录私信
                self.log_message(f"私信: {sender} -> {recipient}: {message}")
                return True
            except:
                # 如果发送失败，客户端可能已断开连接
                if sender != "服务器" and sender in self.nicknames:
                    self.send_message_to_user(sender, f"发送私信给 {recipient} 失败")
                return False
        else:
            # 用户不存在或不在线
            if sender != "服务器" and sender in self.nicknames:
                self.send_message_to_user(sender, f"用户 {recipient} 不存在或未在线")
            return False

    def receive(self):
        # 接收新客户端的连接
        self.server.settimeout(1)  # 设置超时，以便能检查running状态

        while self.running:
            try:
                client, address = self.server.accept()
                self.log_message(f"来自 {address} 的连接...")

                # 发送登录/注册请求
                client.send('AUTH_REQUIRED'.encode('utf-8'))

                # 为客户端创建认证处理线程
                auth_thread = threading.Thread(target=self.handle_authentication, args=(client,))
                auth_thread.daemon = True
                auth_thread.start()
            except socket.timeout:
                continue  # 超时，继续循环
            except Exception as e:
                if self.running:
                    self.log_message(f"接收连接时出错: {str(e)}")
                    time.sleep(1)  # 防止CPU使用过高
                else:
                    break

    def handle_authentication(self, client):
        """处理客户端登录和注册请求"""
        try:
            while True:
                auth_message = client.recv(1024).decode('utf-8')
                if not auth_message:
                    client.close()
                    return

                # 解析认证消息
                if auth_message.startswith("LOGIN:"):
                    # 登录格式: LOGIN:username:password
                    parts = auth_message[6:].split(":")
                    if len(parts) == 2:
                        username, password = parts
                        login_result = self.verify_login(username, password)

                        if login_result == "SUCCESS":
                            # 检查是否已经登录
                            for nick in self.nicknames:
                                if nick == username:
                                    client.send("LOGIN_FAILED:已有同名用户登录".encode('utf-8'))
                                    continue

                            # 登录成功
                            client.send("LOGIN_SUCCESS".encode('utf-8'))
                            self.log_message(f"用户 {username} 登录成功")

                            # 添加到客户端列表
                            self.nicknames.append(username)
                            self.clients.append(client)

                            # 记录用户认证信息
                            self.user_auth[username] = {
                                "client": client,
                                "is_logged_in": True,
                                "is_admin": self.users_data['users'][username].get('is_admin', False),
                                "is_muted": self.users_data['users'][username].get('is_muted', False)
                            }

                            # 更新GUI
                            self.log_message(f"{username} 已加入聊天!")
                            self.clients_label.config(text=f"已连接客户端: {len(self.clients)}")
                            self.update_user_list()

                            # 广播新客户端加入的消息
                            self.broadcast(f"{username} 加入了聊天!".encode('utf-8'))

                            # 添加延迟，确保客户端能正确接收消息
                            time.sleep(0.3)

                            # 向所有客户端发送更新后的用户列表
                            self.broadcast_user_list()

                            # 为客户端创建处理线程
                            client_thread = threading.Thread(target=self.handle, args=(client,))
                            client_thread.daemon = True
                            client_thread.start()

                            return  # 认证成功，退出认证处理
                        else:
                            # 登录失败
                            client.send(f"LOGIN_FAILED:{login_result}".encode('utf-8'))
                    else:
                        client.send("LOGIN_FAILED:格式错误".encode('utf-8'))

                elif auth_message.startswith("REGISTER:"):
                    # 注册格式: REGISTER:username:password
                    parts = auth_message[9:].split(":")
                    if len(parts) == 2:
                        username, password = parts
                        register_result = self.register_user(username, password)

                        if register_result == "SUCCESS":
                            # 注册成功
                            client.send("REGISTER_SUCCESS".encode('utf-8'))
                            self.log_message(f"新用户 {username} 注册成功")
                        else:
                            # 注册失败
                            client.send(f"REGISTER_FAILED:{register_result}".encode('utf-8'))
                    else:
                        client.send("REGISTER_FAILED:格式错误".encode('utf-8'))

                else:
                    # 未知命令
                    client.send("UNKNOWN_COMMAND".encode('utf-8'))
        except Exception as e:
            self.log_message(f"认证处理时出错: {str(e)}")
            try:
                client.close()
            except:
                pass

    def verify_login(self, username, password):
        """验证用户登录"""
        if username in self.users_data['users']:
            # 检查密码是否正确
            stored_password = self.users_data['users'][username]['password']
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            if stored_password == password or stored_password == hashed_password:  # 兼容明文密码和哈希密码
                return "SUCCESS"
            else:
                return "密码错误"
        else:
            return "用户不存在"

    def register_user(self, username, password):
        """注册新用户"""
        if username in self.users_data['users']:
            return "用户名已存在"

        if not username or not password:
            return "用户名和密码不能为空"

        if len(username) < 3 or len(password) < 3:
            return "用户名和密码长度不能小于3"

        # 添加新用户
        self.users_data['users'][username] = {
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "is_admin": False,
            "is_muted": False,
            "registered_date": datetime.datetime.now().isoformat()
        }

        # 保存用户数据
        self.save_users_data()
        return "SUCCESS"

    def send_server_message(self, event=None):
        # 发送服务器公告
        message = self.server_message_entry.get()
        if message:
            self.broadcast(f"[服务器公告] {message}".encode('utf-8'))
            self.log_message(f"[服务器公告] {message}")
            self.server_message_entry.delete(0, END)
        return 'break'  # 防止事件继续传播

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
            history_area.insert(END, f"{message}\n")

        # 按钮框架
        button_frame = ttk.Frame(history_window)
        button_frame.pack(fill=X, padx=10, pady=10)

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
        settings_window.title("服务器设置")
        settings_window.geometry("400x300")
        settings_window.transient(self.root)  # 设置为主窗口的子窗口

        # 设置框架
        settings_frame = ttk.Frame(settings_window, padding=10)
        settings_frame.pack(fill=BOTH, expand=True)

        # 主机设置
        ttk.Label(settings_frame, text="主机:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        host_var = StringVar(value=self.host)
        host_entry = ttk.Entry(settings_frame, textvariable=host_var)
        host_entry.grid(row=0, column=1, sticky=(W, E), padx=5, pady=5)

        # 端口设置
        ttk.Label(settings_frame, text="端口:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
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
        # 保存设置
        restart_needed = False

        if host != self.host or port != self.port:
            restart_needed = True

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
            with open("server_settings.json", "w") as f:
                json.dump(settings, f)
        except Exception as e:
            messagebox.showerror("错误", f"无法保存设置: {str(e)}")

        window.destroy()

        # 如果主机或端口更改，提示重启服务器
        if restart_needed and self.running:
            if messagebox.askyesno("重启服务器", "主机或端口已更改，需要重启服务器才能生效。现在重启服务器吗?"):
                self.stop_server()
                self.address_label.config(text=f"地址: {self.host}:{self.port}")
                self.start_server()
            else:
                messagebox.showinfo("提示", "服务器将继续使用旧的主机和端口，直到重启。")
        else:
            self.address_label.config(text=f"地址: {self.host}:{self.port}")

    def load_settings(self):
        # 从文件加载设置
        settings_file = 'server_settings.json'
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {'host': '0.0.0.0', 'port': 55555, 'max_history': 100}
        else:
            return {'host': '0.0.0.0', 'port': 55555, 'max_history': 100}

    def apply_settings(self):
        # 应用加载的设置
        if 'host' in self.settings:
            self.host = self.settings['host']
        if 'port' in self.settings:
            self.port = self.settings['port']
        if 'max_history' in self.settings:
            self.max_history = self.settings['max_history']

    def load_users_data(self):
        # 加载用户数据
        users_file = 'users.json'
        if os.path.exists(users_file):
            try:
                with open(users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                # 如果加载失败，创建默认用户数据
                return self.create_default_users_data()
        else:
            # 如果文件不存在，创建默认用户数据
            return self.create_default_users_data()

    def create_default_users_data(self):
        # 创建默认用户数据
        default_data = {
            "users": {
                "admin": {
                    "password": hashlib.sha256("123456".encode()).hexdigest(),
                    "is_admin": True,
                    "is_muted": False,
                    "registered_date": datetime.datetime.now().isoformat()
                }
            }
        }
        # 保存默认用户数据
        self.save_users_data(default_data)
        return default_data

    def save_users_data(self, data=None):
        # 保存用户数据
        if data is None:
            data = self.users_data

        users_file = 'users.json'
        try:
            with open(users_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存用户数据失败: {str(e)}")
            return False

    def manage_users(self):
        # 打开用户管理界面
        user_window = Toplevel(self.root)
        user_window.title("用户管理")
        user_window.geometry("700x450")
        user_window.resizable(True, True)
        user_window.transient(self.root)  # 设置为主窗口的子窗口

        # 创建界面
        frame = ttk.Frame(user_window, padding="10")
        frame.pack(fill=BOTH, expand=True)

        # 用户列表
        ttk.Label(frame, text="用户列表:").grid(row=0, column=0, sticky=W, pady=5)

        # 创建表格显示用户信息
        columns = ('用户名', '管理员', '禁言', '注册日期')
        user_tree = ttk.Treeview(frame, columns=columns, show='headings')

        # 设置列标题
        for col in columns:
            user_tree.heading(col, text=col)
            user_tree.column(col, width=100)

        user_tree.grid(row=1, column=0, columnspan=2, sticky=(N, S, E, W))

        # 添加滚动条
        scrollbar = ttk.Scrollbar(frame, orient=VERTICAL, command=user_tree.yview)
        user_tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=1, column=2, sticky=(N, S))

        # 加载用户数据到表格
        self.refresh_user_tree(user_tree)

        # 按钮框架
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=0, columnspan=3, pady=10)

        # 添加用户按钮
        add_btn = ttk.Button(btn_frame, text="添加用户",
                            command=lambda: self.add_user_dialog(user_tree))
        add_btn.pack(side=LEFT, padx=5)

        # 删除用户按钮
        del_btn = ttk.Button(btn_frame, text="删除用户",
                            command=lambda: self.delete_user(user_tree))
        del_btn.pack(side=LEFT, padx=5)

        # 修改密码按钮
        pwd_btn = ttk.Button(btn_frame, text="修改密码",
                            command=lambda: self.change_password_dialog(user_tree))
        pwd_btn.pack(side=LEFT, padx=5)

        # 禁言/解禁按钮
        mute_btn = ttk.Button(btn_frame, text="禁言/解禁",
                             command=lambda: self.toggle_mute(user_tree))
        mute_btn.pack(side=LEFT, padx=5)

        # 设置/取消管理员按钮
        admin_btn = ttk.Button(btn_frame, text="设置/取消管理员",
                              command=lambda: self.toggle_admin(user_tree))
        admin_btn.pack(side=LEFT, padx=5)

        # 设置网格权重
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        # 刷新按钮
        refresh_btn = ttk.Button(frame, text="刷新",
                                command=lambda: self.refresh_user_tree(user_tree))
        refresh_btn.grid(row=2, column=2, sticky=E, padx=5)

        # 操作说明
        help_frame = ttk.LabelFrame(frame, text="操作说明")
        help_frame.grid(row=3, column=0, columnspan=3, sticky=(W, E), padx=5, pady=10)

        help_text = "添加用户: 创建新用户账号\n"
        help_text += "删除用户: 删除选中的用户账号\n"
        help_text += "修改密码: 修改选中用户的密码\n"
        help_text += "禁言/解禁: 允许或禁止用户在聊天室发言\n"
        help_text += "设置/取消管理员: 赋予或取消用户的管理员权限\n"

        ttk.Label(help_frame, text=help_text, justify=LEFT).pack(padx=5, pady=5, anchor=W)

    def refresh_user_tree(self, tree):
        # 刷新用户列表
        # 清空表格
        for item in tree.get_children():
            tree.delete(item)

        # 添加用户数据
        for username, user_info in self.users_data['users'].items():
            is_admin = "是" if user_info.get('is_admin', False) else "否"
            is_muted = "是" if user_info.get('is_muted', False) else "否"
            reg_date = user_info.get('registered_date', "未知")

            tree.insert('', 'end', values=(username, is_admin, is_muted, reg_date))

    def change_password_dialog(self, tree):
        # 修改密码对话框
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要修改密码的用户")
            return

        username = tree.item(selected, 'values')[0]

        change_window = Toplevel(self.root)
        change_window.title("修改密码")
        change_window.geometry("300x200")
        change_window.transient(self.root)  # 设置为主窗口的子窗口

        # 输入框架
        input_frame = ttk.Frame(change_window, padding="10")
        input_frame.pack(fill=BOTH, expand=True)

        # 用户名显示（不可编辑）
        ttk.Label(input_frame, text="用户名:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        username_label = ttk.Label(input_frame, text=username)
        username_label.grid(row=0, column=1, sticky=(W, E), padx=5, pady=5)

        # 新密码输入
        ttk.Label(input_frame, text="新密码:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        new_password_entry = ttk.Entry(input_frame, show="*")
        new_password_entry.grid(row=1, column=1, sticky=(W, E), padx=5, pady=5)

        # 显示新密码复选框
        show_new_pwd_var = BooleanVar()
        show_new_pwd_check = ttk.Checkbutton(input_frame, text="显示",
                                           variable=show_new_pwd_var,
                                           command=lambda: new_password_entry.config(show="" if show_new_pwd_var.get() else "*"))
        show_new_pwd_check.grid(row=1, column=2, padx=5, pady=5)

        # 确认新密码输入
        ttk.Label(input_frame, text="确认新密码:").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        confirm_new_password_entry = ttk.Entry(input_frame, show="*")
        confirm_new_password_entry.grid(row=2, column=1, sticky=(W, E), padx=5, pady=5)

        # 显示确认新密码复选框
        show_confirm_pwd_var = BooleanVar()
        show_confirm_pwd_check = ttk.Checkbutton(input_frame, text="显示",
                                               variable=show_confirm_pwd_var,
                                               command=lambda: confirm_new_password_entry.config(show="" if show_confirm_pwd_var.get() else "*"))
        show_confirm_pwd_check.grid(row=2, column=2, padx=5, pady=5)

        # 按钮框架
        btn_frame = ttk.Frame(change_window)
        btn_frame.pack(fill=X, padx=10, pady=10)

        # 修改按钮
        change_btn = ttk.Button(btn_frame, text="修改",
                               command=lambda: self.admin_change_password(username, new_password_entry.get(), confirm_new_password_entry.get(), change_window, tree))
        change_btn.pack(side=LEFT, padx=5)

        # 取消按钮
        cancel_btn = ttk.Button(btn_frame, text="取消", command=change_window.destroy)
        cancel_btn.pack(side=RIGHT, padx=5)

    def admin_change_password(self, username, new_password, confirm_new_password, window, tree):
        # 管理员修改密码（不需要旧密码）
        if username and new_password and confirm_new_password:
            if new_password == confirm_new_password:
                # 检查用户名是否存在
                if username in self.users_data['users']:
                    # 修改密码
                    self.users_data['users'][username]['password'] = hashlib.sha256(new_password.encode()).hexdigest()
                    self.save_users_data()
                    messagebox.showinfo("成功", f"已成功修改用户 {username} 的密码")
                    window.destroy()
                else:
                    messagebox.showerror("错误", "用户名不存在")
            else:
                messagebox.showerror("错误", "新密码不一致")
        else:
            messagebox.showerror("错误", "请填写所有信息")

    def add_user_dialog(self, tree):
        # 添加用户对话框
        add_window = Toplevel(self.root)
        add_window.title("添加用户")
        add_window.geometry("300x200")
        add_window.transient(self.root)  # 设置为主窗口的子窗口

        # 输入框架
        input_frame = ttk.Frame(add_window, padding="10")
        input_frame.pack(fill=BOTH, expand=True)

        # 用户名输入
        ttk.Label(input_frame, text="用户名:").grid(row=0, column=0, sticky=W, padx=5, pady=5)
        username_entry = ttk.Entry(input_frame)
        username_entry.grid(row=0, column=1, sticky=(W, E), padx=5, pady=5)

        # 密码输入
        ttk.Label(input_frame, text="密码:").grid(row=1, column=0, sticky=W, padx=5, pady=5)
        password_entry = ttk.Entry(input_frame, show="*")
        password_entry.grid(row=1, column=1, sticky=(W, E), padx=5, pady=5)

        # 确认密码输入
        ttk.Label(input_frame, text="确认密码:").grid(row=2, column=0, sticky=W, padx=5, pady=5)
        confirm_password_entry = ttk.Entry(input_frame, show="*")
        confirm_password_entry.grid(row=2, column=1, sticky=(W, E), padx=5, pady=5)

        # 按钮框架
        btn_frame = ttk.Frame(add_window)
        btn_frame.pack(fill=X, padx=10, pady=10)

        # 添加按钮
        add_btn = ttk.Button(btn_frame, text="添加",
                            command=lambda: self.add_user(username_entry.get(), password_entry.get(), confirm_password_entry.get(), add_window, tree))
        add_btn.pack(side=LEFT, padx=5)

        # 取消按钮
        cancel_btn = ttk.Button(btn_frame, text="取消", command=add_window.destroy)
        cancel_btn.pack(side=RIGHT, padx=5)

    def add_user(self, username, password, confirm_password, window, tree):
        # 添加用户
        if username and password and confirm_password:
            if password == confirm_password:
                # 检查用户名是否已存在
                if username in self.users_data['users']:
                    messagebox.showerror("错误", "用户名已存在")
                else:
                    # 添加用户
                    self.users_data['users'][username] = {
                        "password": hashlib.sha256(password.encode()).hexdigest(),
                        "is_admin": False,
                        "is_muted": False,
                        "registered_date": datetime.datetime.now().isoformat()
                    }
                    self.save_users_data()
                    self.refresh_user_tree(tree)
                    window.destroy()
            else:
                messagebox.showerror("错误", "密码不一致")
        else:
            messagebox.showerror("错误", "请填写所有信息")

    def delete_user(self, tree):
        # 删除用户
        selected = tree.selection()
        if selected:
            username = tree.item(selected, 'values')[0]
            if messagebox.askyesno("确认", f"确定要删除用户 {username} 吗?"):
                del self.users_data['users'][username]
                self.save_users_data()
                self.refresh_user_tree(tree)
        else:
            messagebox.showinfo("提示", "请先选择要删除的用户")

    def change_password(self, username, old_password, new_password, confirm_new_password, window, tree):
        # 修改密码
        if username and old_password and new_password and confirm_new_password:
            if new_password == confirm_new_password:
                # 检查用户名是否存在
                if username in self.users_data['users']:
                    # 检查旧密码是否正确
                    if self.users_data['users'][username]['password'] == hashlib.sha256(old_password.encode()).hexdigest():
                        # 修改密码
                        self.users_data['users'][username]['password'] = hashlib.sha256(new_password.encode()).hexdigest()
                        self.save_users_data()
                        window.destroy()
                    else:
                        messagebox.showerror("错误", "旧密码不正确")
                else:
                    messagebox.showerror("错误", "用户名不存在")
            else:
                messagebox.showerror("错误", "新密码不一致")
        else:
            messagebox.showerror("错误", "请填写所有信息")

    def toggle_mute(self, tree):
        # 切换禁言状态
        selected = tree.selection()
        if selected:
            username = tree.item(selected, 'values')[0]
            if self.users_data['users'][username]['is_muted']:
                self.users_data['users'][username]['is_muted'] = False
            else:
                self.users_data['users'][username]['is_muted'] = True
            self.save_users_data()
            self.refresh_user_tree(tree)
        else:
            messagebox.showinfo("提示", "请先选择要切换禁言状态的用户")

    def toggle_admin(self, tree):
        # 切换管理员状态
        selected = tree.selection()
        if selected:
            username = tree.item(selected, 'values')[0]
            if self.users_data['users'][username]['is_admin']:
                self.users_data['users'][username]['is_admin'] = False
            else:
                self.users_data['users'][username]['is_admin'] = True
            self.save_users_data()
            self.refresh_user_tree(tree)
        else:
            messagebox.showinfo("提示", "请先选择要切换管理员状态的用户")

    def exit_app(self):
        if messagebox.askokcancel("退出", "确定要退出服务器吗?"):
            if self.running:
                self.stop_server()
            self.root.destroy()

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
        self.root.mainloop()

    def save_current_settings(self):
        """保存当前服务器设置"""
        # 保存设置到文件
        settings = {
            "host": self.host,
            "port": self.port,
            "max_history": self.max_history
        }

        try:
            with open("server_settings.json", "w") as f:
                json.dump(settings, f)
        except Exception as e:
            messagebox.showerror("错误", f"无法保存设置: {str(e)}")

    def update_user_list(self):
        """更新GUI中的用户列表显示"""
        # 清空当前列表
        self.users_listbox.delete(0, END)

        # 添加所有用户
        for nickname in self.nicknames:
            # 检查用户是否是管理员
            is_admin = False
            is_muted = False
            if nickname in self.users_data['users']:
                is_admin = self.users_data['users'][nickname].get('is_admin', False)
                is_muted = self.users_data['users'][nickname].get('is_muted', False)

            # 显示用户状态标记
            display_name = nickname
            if is_admin:
                display_name = f"{nickname} [管理员]"
            if is_muted:
                display_name = f"{display_name} [已禁言]"

            self.users_listbox.insert(END, display_name)

        # 更新客户端计数
        self.clients_label.config(text=f"已连接客户端: {len(self.clients)}")

    def broadcast_user_list(self):
        """向所有客户端广播用户列表"""
        # 构建完整的用户状态列表
        user_status_list = []
        for nickname in self.nicknames:
            # 获取用户状态
            is_admin = False
            is_muted = False
            if nickname in self.users_data['users']:
                is_admin = self.users_data['users'][nickname].get('is_admin', False)
                is_muted = self.users_data['users'][nickname].get('is_muted', False)

            # 添加到状态列表
            user_status_list.append({
                "username": nickname,
                "is_admin": is_admin,
                "is_muted": is_muted
            })

        # 将用户列表转换为JSON字符串
        user_list_json = json.dumps(user_status_list)

        # 广播用户列表（JSON格式）
        user_list_message = f"USER_LIST:{user_list_json}"

        # 同时发送简单格式的用户列表，以兼容客户端
        simple_user_list = ",".join(self.nicknames)
        simple_user_list_message = f"USER_LIST:{simple_user_list}"

        for client in self.clients:
            try:
                # 发送JSON格式的用户列表
                client.send(user_list_message.encode('utf-8'))

                # 添加足够的延迟，确保消息不会混合
                time.sleep(0.3)  # 增加延迟时间，避免消息混淆

                # 发送简单格式的用户列表（确保客户端能够正确显示）
                client.send(simple_user_list_message.encode('utf-8'))
            except:
                # 如果发送失败，客户端可能已断开连接
                pass

    def send_user_list(self, client):
        """向特定客户端发送用户列表"""
        # 构建完整的用户状态列表
        user_status_list = []
        for nickname in self.nicknames:
            # 获取用户状态
            is_admin = False
            is_muted = False
            if nickname in self.users_data['users']:
                is_admin = self.users_data['users'][nickname].get('is_admin', False)
                is_muted = self.users_data['users'][nickname].get('is_muted', False)

            # 添加到状态列表
            user_status_list.append({
                "username": nickname,
                "is_admin": is_admin,
                "is_muted": is_muted
            })

        # 将用户列表转换为JSON字符串
        user_list_json = json.dumps(user_status_list)

        # 发送JSON格式的用户列表
        user_list_message = f"USER_LIST:{user_list_json}"

        # 同时发送简单格式的用户列表，以兼容客户端
        simple_user_list = ",".join(self.nicknames)
        simple_user_list_message = f"USER_LIST:{simple_user_list}"

        try:
            # 发送JSON格式的用户列表
            client.send(user_list_message.encode('utf-8'))

            # 发送简单格式的用户列表（确保客户端能够正确显示）
            time.sleep(0.1)  # 短暂延迟，避免消息混淆
            client.send(simple_user_list_message.encode('utf-8'))
        except:
            # 如果发送失败，客户端可能已断开连接
            pass

    def send_detailed_user_list(self, client):
        """向特定客户端发送详细用户列表（只包含JSON格式，不发送简单格式）"""
        # 构建完整的用户状态列表
        user_status_list = []
        for nickname in self.nicknames:
            # 获取用户状态
            is_admin = False
            is_muted = False
            if nickname in self.users_data['users']:
                is_admin = self.users_data['users'][nickname].get('is_admin', False)
                is_muted = self.users_data['users'][nickname].get('is_muted', False)

            # 添加到状态列表
            user_status_list.append({
                "username": nickname,
                "is_admin": is_admin,
                "is_muted": is_muted
            })

        # 将用户列表转换为JSON字符串
        user_list_json = json.dumps(user_status_list)

        # 发送JSON格式的用户列表
        user_list_message = f"USER_LIST:{user_list_json}"

        try:
            # 只发送JSON格式的用户列表，不发送简单格式
            client.send(user_list_message.encode('utf-8'))
        except:
            # 如果发送失败，客户端可能已断开连接
            pass

if __name__ == "__main__":
    server = ChatServer()
    server.run()
