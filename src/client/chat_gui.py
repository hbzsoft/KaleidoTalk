# chat_gui.py
# Copyright (C) 2026 Bangze Han
# -*- coding: utf-8 -*-

# This file is part of KaleidoTalk.

# KaleidoTalk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

# KaleidoTalk is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with KaleidoTalk. If not, see <https://www.gnu.org/licenses/>.


# chat_gui.py
import tkinter as tk
import queue
import re
import time
import threading
import customtkinter as ctk
from src.client.chat_client import ChatClient, flash_taskbar
from src.common.crypto_utils import (
    IdentityKeyManager,
    FingerprintWords,
)

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None


# ----------------------------------------------------------------------
class ChatGUI:
    """图形界面"""
    USER_LIST_REFRESH_MS = 5000

    def __init__(self):
        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        default_font = ('Verdana', 10)
        self.root.option_add('*Font', default_font)
        self.root.option_add('*Dialog.msg.Font', default_font)
        self.root.title("KaleidoTalk V2.3")
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width = min(1100, max(900, screen_w - 120))
        height = min(760, max(650, screen_h - 140))
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(900, 650)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.bind("<Unmap>", self.on_window_unmap)

        self.message_queue = queue.Queue()
        self.client = ChatClient()
        self.client.callback = self.on_message_received
        self.client.cert_verify_callback = self._cert_verify_dialog
        self._pending_register = None

        self.is_minimized_to_tray = False
        self._tray_minimize_pending = False
        self.tray_icon = None
        self.is_exiting = False
        self._context_menu = None
        self._context_menu_user = None
        self._displayed_users = []
        self._user_rows = {}
        self.selected_user = None
        self._color_palette = [
            '#1f77b4',
            '#2ca02c',
            '#d62728',
            '#9467bd',
            '#ff7f0e',
            '#17becf',
            '#8c564b',
        ]
        self._name_colors = {}

        self.setup_ui()
        self.root.after(100, self.process_messages)
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)
        self.root.after(300, self.connect_to_server)

    # ------------------------------------------------------------------
    # UI 构建
    def setup_ui(self):
        main_frame = ctk.CTkFrame(self.root, corner_radius=0)
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # 工具栏
        toolbar = ctk.CTkFrame(main_frame, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        self.status_label = ctk.CTkLabel(toolbar, text="未连接", text_color="#ff6b6b")
        self.status_label.pack(side=tk.LEFT, padx=(0, 10))

        self.user_label = ctk.CTkLabel(toolbar, text="未登录")
        self.user_label.pack(side=tk.LEFT, padx=(0, 10))
        self.user_label.bind("<Button-1>", self._on_user_label_click)

        self.crypto_label = ctk.CTkLabel(toolbar, text="🔓 无加密", text_color="#ff6b6b")
        self.crypto_label.pack(side=tk.LEFT, padx=(0, 10))

        self.connect_btn = ctk.CTkButton(toolbar, text="连接", command=self.connect_to_server, corner_radius=8)
        self.connect_btn.pack(side=tk.LEFT, padx=2)

        self.register_btn = ctk.CTkButton(toolbar, text="注册", command=self.register_user, state=tk.DISABLED, corner_radius=8)
        self.register_btn.pack(side=tk.LEFT, padx=2)

        self.login_btn = ctk.CTkButton(toolbar, text="登录", command=self.login_user, state=tk.DISABLED, corner_radius=8)
        self.login_btn.pack(side=tk.LEFT, padx=2)

        self.logout_btn = ctk.CTkButton(toolbar, text="登出", command=self.logout_user, state=tk.DISABLED, corner_radius=8)
        self.logout_btn.pack(side=tk.LEFT, padx=2)
        self.about_btn = ctk.CTkButton(toolbar, text="关于", command=self.show_about, corner_radius=8)
        self.about_btn.pack(side=tk.LEFT, padx=2)

        # 聊天区域
        chat_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        chat_frame.grid(row=1, column=0, sticky="nsew")
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)

        self.chat_display = ctk.CTkTextbox(
            chat_frame, wrap="word", width=50, height=20, state=tk.DISABLED, corner_radius=8)
        self.chat_display.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        # 在线用户列表
        users_frame = ctk.CTkFrame(chat_frame, corner_radius=8)
        users_frame.grid(row=0, column=1, sticky="ns")
        ctk.CTkLabel(users_frame, text="在线用户", font=("Verdana", 12, "bold")).pack(anchor="w", padx=8, pady=(8, 4))
        header = ctk.CTkFrame(users_frame, fg_color="transparent")
        header.pack(fill=tk.X, padx=8, pady=(0, 4))
        ctk.CTkLabel(header, text="用户", width=120, anchor="w").pack(side=tk.LEFT)
        ctk.CTkLabel(header, text="信任", width=50, anchor="e").pack(side=tk.RIGHT)
        self.users_list_frame = ctk.CTkScrollableFrame(users_frame, width=220, height=460, corner_radius=6)
        self.users_list_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # 发送区域
        send_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        send_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        send_frame.columnconfigure(0, weight=1)

        receiver_frame = ctk.CTkFrame(send_frame, fg_color="transparent")
        receiver_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        ctk.CTkLabel(receiver_frame, text="发送给:").pack(side=tk.LEFT, padx=(0, 5))
        self.receiver_entry = ctk.CTkEntry(receiver_frame, width=150, corner_radius=6)
        self.receiver_entry.pack(side=tk.LEFT)

        input_frame = ctk.CTkFrame(send_frame, fg_color="transparent")
        input_frame.grid(row=1, column=0, sticky="ew")
        input_frame.columnconfigure(0, weight=1)

        self.message_entry = ctk.CTkEntry(input_frame, corner_radius=6)
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        self.send_btn = ctk.CTkButton(input_frame, text="发送", command=self.send_message, state=tk.DISABLED, corner_radius=8)
        self.send_btn.grid(row=0, column=1)

        self.update_button_states()

    # ------------------------------------------------------------------
    # 按钮状态
    def update_button_states(self):
        if self.client and self.client.sock:
            self.connect_btn.configure(state=tk.DISABLED)
            if self.client.server_ed25519_pub:
                self.register_btn.configure(state=tk.NORMAL)
                self.login_btn.configure(state=tk.NORMAL)
            else:
                self.register_btn.configure(state=tk.DISABLED)
                self.login_btn.configure(state=tk.DISABLED)

            if self.client.session_id and self.client.session_key:
                self.logout_btn.configure(state=tk.NORMAL)
                self.send_btn.configure(state=tk.NORMAL)
                self.user_label.configure(text=f"用户: {self.client.username}")
                self.crypto_label.configure(text="🔐 端到端加密", text_color="#6ee7b7")
            else:
                self.logout_btn.configure(state=tk.DISABLED)
                self.send_btn.configure(state=tk.DISABLED)
                self.user_label.configure(text="未登录")
                self.crypto_label.configure(text="🔓 未加密", text_color="#ff6b6b")
        else:
            self.connect_btn.configure(state=tk.NORMAL)
            self.register_btn.configure(state=tk.DISABLED)
            self.login_btn.configure(state=tk.DISABLED)
            self.logout_btn.configure(state=tk.DISABLED)
            self.send_btn.configure(state=tk.DISABLED)
            self.status_label.configure(text="未连接", text_color="#ff6b6b")
            self.user_label.configure(text="未登录")
            self.crypto_label.configure(text="🔓 未加密", text_color="#ff6b6b")

    # ------------------------------------------------------------------
    def _dialog_input(self, title, prompt, show=None, initial=''):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("420x190")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=prompt, wraplength=350).pack(pady=(20, 10), padx=20)
        var = tk.StringVar(value=initial)
        entry = ctk.CTkEntry(dlg, textvariable=var, width=280, show=show, corner_radius=6)
        entry.pack(pady=(0, 10))
        entry.focus_set()
        result = None

        def on_ok():
            nonlocal result
            result = var.get()
            dlg.destroy()

        def on_cancel():
            dlg.destroy()

        entry.bind('<Return>', lambda e: on_ok())
        entry.bind('<Escape>', lambda e: on_cancel())
        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack()
        ctk.CTkButton(btn_frame, text="确定", command=on_ok, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="取消", command=on_cancel, width=90, corner_radius=8).pack(side=tk.LEFT, padx=5)

        self.center_dialog(dlg)
        dlg.update_idletasks()
        entry.focus_force()
        self.root.wait_window(dlg)
        return result

    def _dialog_choice(self, title, message, choices):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("560x300")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=message, justify=tk.LEFT, wraplength=450).pack(pady=(20, 10), padx=20)
        sel_var = tk.IntVar(value=-1)
        list_frame = ctk.CTkScrollableFrame(dlg, width=450, height=120, corner_radius=6)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        for idx, (text, val) in enumerate(choices):
            row = ctk.CTkFrame(list_frame, fg_color="transparent")
            row.pack(fill=tk.X, pady=4)
            rb = ctk.CTkRadioButton(row, text="", variable=sel_var, value=idx)
            rb.pack(side=tk.LEFT)
            lbl = ctk.CTkLabel(row, text=text, wraplength=420, justify=tk.LEFT)
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6,0))
            if idx == 0:
                first_rb = rb

        result = [None]

        def on_ok():
            idx = sel_var.get()
            if idx is None or idx < 0 or idx >= len(choices):
                result[0] = None
            else:
                result[0] = choices[idx][1]
            dlg.destroy()

        def on_cancel():
            result[0] = None
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=8)
        ctk.CTkButton(btn_frame, text="确定", command=on_ok, width=110, corner_radius=8).pack(side=tk.LEFT, padx=6)
        ctk.CTkButton(btn_frame, text="取消", command=on_cancel, width=110, corner_radius=8).pack(side=tk.LEFT, padx=6)

        dlg.bind('<Escape>', lambda e: on_cancel())
        self.center_dialog(dlg)
        dlg.update_idletasks()
        if 'first_rb' in locals():
            first_rb.focus_force()
        self.root.wait_window(dlg)
        return result[0]

    def _dialog_showinfo(self, title, message):
        self._dialog_message(title, message)

    def _dialog_showerror(self, title, message):
        self._dialog_message(title, message)

    def _dialog_message(self, title, message):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("560x320")
        dlg.resizable(True, True)

        content_frame = ctk.CTkScrollableFrame(dlg, corner_radius=6)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(20, 12))
        ctk.CTkLabel(content_frame, text=message, justify=tk.LEFT, wraplength=500).pack(anchor="w", fill=tk.BOTH, expand=True)

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=(0, 14))
        ctk.CTkButton(btn_frame, text="确定", command=dlg.destroy, width=100, corner_radius=8).pack()

        dlg.bind('<Escape>', lambda e: dlg.destroy())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)

    # ------------------------------------------------------------------
    # TLS 证书 BIP39 确认对话框
    def _cert_verify_dialog(self, endpoint, fingerprint):
        words = FingerprintWords.fingerprint_to_words(fingerprint, 6)
        words_str = "  ".join(words).upper()

        dlg = ctk.CTkToplevel(self.root)
        dlg.title("TLS 证书验证")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("700x430")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=f"首次连接 {endpoint}，请核对服务器 TLS 证书指纹：", wraplength=600, font=("", 11, "bold")).pack(pady=10)

        word_frame = ctk.CTkFrame(dlg)
        word_frame.pack(pady=15, padx=20, fill=tk.X)
        ctk.CTkLabel(word_frame, text="指纹单词（6个）:", font=("", 10, "bold")).pack(anchor="w", pady=(0, 8))
        ctk.CTkLabel(word_frame, text=words_str, font=("", 16, "bold"), text_color=("#0066ff", "#6699ff")).pack(anchor="w", pady=10, padx=10)

        ctk.CTkLabel(dlg, text="请通过其他安全渠道（电话、当面）核对以上单词。", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=5)

        result = [False]

        def trust():
            result[0] = True
            dlg.destroy()

        def reject():
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="信任", command=trust, width=100, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="拒绝", command=reject, width=100, corner_radius=8).pack(side=tk.LEFT, padx=5)

        dlg.bind('<Escape>', lambda e: reject())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    # ------------------------------------------------------------------
    def show_about(self):
        about_text = (
            "KaleidoTalk 聊天软件\n"
            "版本 2.3\n"
            "Copyright (C) 2026 Bangze Han\n\n"
            "This program is free software: you can redistribute it and/or modify\n"
            "it under the terms of the GNU General Public License as published by\n"
            "the Free Software Foundation, either version 3 of the License, or\n"
            "(at your option) any later version.\n\n"
            "This program is distributed in the hope that it will be useful,\n"
            "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"
            "You should have received a copy of the GNU General Public License\n"
            "along with this program. If not, see <https://www.gnu.org/licenses/>.\n\n"
            "使用第三方库：\n"
            "- cryptography (Apache 2.0)\n"
            "- pystray (LGPLv3)\n"
            "- PIL (MIT 衍生)\n"
            "- CustomTkinker (MIT)\n"
        )
        self._dialog_showinfo("关于 KaleidoTalk", about_text)

    def center_dialog(self, dialog):
        dialog.update_idletasks()
        req_w = max(dialog.winfo_width(), dialog.winfo_reqwidth())
        req_h = max(dialog.winfo_height(), dialog.winfo_reqheight())
        screen_w = dialog.winfo_screenwidth()
        screen_h = dialog.winfo_screenheight()
        w = min(req_w, max(320, screen_w - 80))
        h = min(req_h, max(180, screen_h - 120))
        x = max(0, (screen_w // 2) - (w // 2))
        y = max(0, (screen_h // 2) - (h // 2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')

    # ------------------------------------------------------------------
    # 连接与登录流程
    def connect_to_server(self):
        addr = self._dialog_input("连接服务器", "输入 地址:端口", initial="127.0.0.1:5555")
        if not addr:
            return
        try:
            host, port = addr.split(':')
            port = int(port)
        except:
            host, port = "127.0.0.1", 5555
        self.client.host = host
        self.client.port = port
        self.client.callback = self.on_message_received
        ok = self.client.connect()
        if ok:
            self.status_label.configure(text="已连接 (TLS)", text_color="#6ee7b7")
            self.append_chat("系统", "已连接到服务器 (TLS)", "green")
        else:
            self.status_label.configure(text="连接失败", text_color="#ff6b6b")
            self._dialog_showerror("错误", "无法连接到服务器")
        self.update_button_states()

    def register_user(self):
        if not self.client.server_ed25519_pub:
            self._dialog_showerror("错误", "服务器公钥未就绪")
            return
        if self.client.session_id and self.client.session_key:
            self.client.logout()
            self.append_chat("系统", "检测到当前账号已登录，已自动登出后继续注册")
        username = self._dialog_input("注册", "用户名 (3-20字母数字):")
        if not username or not re.match(r'^[A-Za-z0-9]{3,20}$', username):
            return
        pw = self._dialog_input("注册", "密码 (至少8位，含字母和数字):", show='*')
        if not pw or len(pw) < 8:
            return

        choice = self._dialog_choice("私钥存储", "请选择私钥保存方式:",
                                     [("存储到服务器 (可在任何设备登录)", True),
                                      ("仅本地存储 (私钥不离开本机)", False)])
        if choice is None:
            return

        self._pending_register = {
            'username': username,
            'password': pw,
            'store_private_key': choice,
            'invite_code': '',
        }

        invite = ''
        if self._reg_policy_required():
            invite = self._dialog_input("邀请码", "请输入邀请码:")
            if not invite:
                self._pending_register = None
                return
            self._pending_register['invite_code'] = invite

        self.client.register(username, pw, store_private_key=choice, invite_code=invite)

    def _reg_policy_required(self):
        return bool(self.client.require_invite_for_register)

    def login_user(self):
        if not self.client.server_ed25519_pub:
            self._dialog_showerror("错误", "服务器公钥未就绪")
            return
        username = self._dialog_input("登录", "用户名:")
        if not username:
            return
        pw = self._dialog_input("登录", "密码:", show='*')
        if not pw:
            return
        self.client.login(username, pw)

    def logout_user(self):
        self.client.logout()
        self.append_chat("系统", "已登出")

    # ------------------------------------------------------------------
    # 消息发送与显示
    def send_message(self):
        receiver = self.receiver_entry.get().strip()
        msg = self.message_entry.get().strip()
        if not receiver or not msg:
            return
        if self.client.send_message(receiver, msg):
            self.append_chat("我", f"-> {receiver}: {msg}")
            self.message_entry.delete(0, tk.END)

    def append_chat(self, source, message, color=None):
        self.chat_display.configure(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {source}: {message}\n"
        if color is None or color == 'auto':
            color = self._color_for_name(source)
        tag_name = f"fg_{color.lstrip('#').replace(' ', '_')}"
        text_widget = self.chat_display._textbox if hasattr(self.chat_display, '_textbox') else self.chat_display
        text_widget.tag_configure(tag_name, foreground=color)
        start_index = text_widget.index(tk.END)
        text_widget.insert(tk.END, line)
        end_index = text_widget.index(tk.END)
        text_widget.tag_add(tag_name, start_index, end_index)
        text_widget.see(tk.END)
        self.chat_display.configure(state=tk.DISABLED)

    def _color_for_name(self, name):
        if name in self._name_colors:
            return self._name_colors[name]
        color = self._color_palette[len(self._name_colors) % len(self._color_palette)]
        self._name_colors[name] = color
        return color

    # ------------------------------------------------------------------
    # 回调处理
    def on_message_received(self, msg_type, content):
        self.message_queue.put((msg_type, content))

    def process_messages(self):
        try:
            while True:
                msg_type, content = self.message_queue.get_nowait()
                self.handle_message(msg_type, content)
        except queue.Empty:
            pass
        self.root.after(100, self.process_messages)

    def handle_message(self, msg_type, content):
        if msg_type == 'SYS':
            self.append_chat("系统", content)
        elif msg_type == 'ERROR':
            if content == 'invite_required' and self._pending_register is not None:
                invite = self._dialog_input("邀请码", "该服务器要求邀请码，请输入邀请码:")
                if invite:
                    self._pending_register['invite_code'] = invite
                    self.client.register(
                        self._pending_register['username'],
                        self._pending_register['password'],
                        store_private_key=self._pending_register['store_private_key'],
                        invite_code=invite,
                    )
                    return
            self.append_chat("错误", content)
        elif msg_type == 'SUCCESS':
            self.append_chat("成功", content)
            if isinstance(content, str) and ('注册成功' in content):
                registered_username = None
                if self._pending_register:
                    registered_username = self._pending_register.get('username')
                self._pending_register = None
                self.root.after(500, lambda u=registered_username: self._show_own_fingerprint_after_register(u))
            self.update_button_states()
        elif msg_type == 'MESSAGE':
            if isinstance(content, dict):
                sender = content.get('sender', '消息')
                message = content.get('message', '')
                self.append_chat(sender, message)
            else:
                self.append_chat("消息", content)
            if self.is_minimized_to_tray:
                if isinstance(content, dict):
                    self._tray_notify(f"{content.get('sender', '消息')}: {content.get('message', '')}")
                else:
                    self._tray_notify(content)
            else:
                flash_taskbar(self.root)
        elif msg_type == 'USERS':
            self._update_user_list(content)
        elif msg_type == 'WARNING':
            self.append_chat("警告", content)
        elif msg_type == 'USER_VERIFY':
            username = content.get('username', '')
            finger = content.get('fingerprint', '')
            approved = self._show_user_fingerprint_dialog(username, finger)
            if approved:
                self.client.trust_user(username)
            else:
                self.client._end_verification(username)
        elif msg_type == 'UPDATE_BUTTONS':
            self.update_button_states()
        else:
            self.append_chat("原始", str(content), "gray")

    # ------------------------------------------------------------------
    # 用户列表
    def _update_user_list(self, users):
        for widget in self.users_list_frame.winfo_children():
            widget.destroy()

        filtered_users = [u for u in users if u != self.client.username]
        self._displayed_users = filtered_users
        self._user_rows.clear()

        if self.selected_user and self.selected_user not in filtered_users:
            self.selected_user = None

        for u in filtered_users:
            trust_status = "✓" if self.client._is_user_trusted(u) else "?"
            row = ctk.CTkFrame(self.users_list_frame, corner_radius=6)
            row.pack(fill=tk.X, pady=2, padx=2)

            name_label = ctk.CTkLabel(row, text=u, anchor='w')
            name_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 4), pady=6)
            trust_label = ctk.CTkLabel(row, text=trust_status, width=30, anchor='e')
            trust_label.pack(side=tk.RIGHT, padx=(4, 8), pady=6)

            self._user_rows[u] = row
            self._bind_user_row_events(row, name_label, trust_label, u)

        if self.selected_user:
            self._select_user(self.selected_user)

    def refresh_online_users(self):
        if self.client and self.client.sock and self.client.session_id and self.client.session_key:
            self.client._request_online_users()
        self.root.after(self.USER_LIST_REFRESH_MS, self.refresh_online_users)

    def _bind_user_row_events(self, row, name_label, trust_label, username):
        for widget in (row, name_label, trust_label):
            widget.bind("<Button-1>", lambda e, u=username: self._on_user_click(u))
            widget.bind("<Double-1>", lambda e, u=username: self.on_user_double_click(u))
            widget.bind("<Button-3>", lambda e, u=username: self.on_tree_right_click(e, u))

    def _on_user_click(self, username):
        self._select_user(username)

    def _select_user(self, username):
        self.selected_user = username
        for u, row in self._user_rows.items():
            if u == username:
                row.configure(fg_color=("#d9d9d9", "#2f2f2f"))
            else:
                row.configure(fg_color=("#f2f2f2", "#343638"))

    def on_tree_right_click(self, event, username=None):
        if username:
            self._select_user(username)
        if self.selected_user:
            self._show_context_menu(event.x_root, event.y_root, self.selected_user)

    def _show_context_menu(self, x, y, username):
        self._close_context_menu()
        self._context_menu_user = username
        menu = ctk.CTkToplevel(self.root)
        menu.overrideredirect(True)
        menu.attributes('-topmost', True)
        menu.geometry(f"180x160+{x}+{y}")

        container = ctk.CTkFrame(menu, corner_radius=8)
        container.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        ctk.CTkButton(container, text="验证指纹", corner_radius=8,
                      command=lambda: self._menu_action(self.verify_selected_user)).pack(fill=tk.X, padx=8, pady=(8, 4))
        ctk.CTkButton(container, text="移除信任", corner_radius=8,
                      command=lambda: self._menu_action(self.distrust_selected_user)).pack(fill=tk.X, padx=8, pady=4)
        ctk.CTkButton(container, text="复制指纹", corner_radius=8,
                      command=lambda: self._menu_action(self.copy_fingerprint)).pack(fill=tk.X, padx=8, pady=4)
        ctk.CTkButton(container, text="关闭", corner_radius=8,
                      command=self._close_context_menu).pack(fill=tk.X, padx=8, pady=(4, 8))

        menu.bind("<FocusOut>", lambda e: self._close_context_menu())
        menu.focus_force()
        self._context_menu = menu

    def _menu_action(self, action):
        self._close_context_menu()
        action()

    def _close_context_menu(self):
        if self._context_menu:
            try:
                self._context_menu.destroy()
            except Exception:
                pass
        self._context_menu = None

    def on_user_double_click(self, username=None):
        if not username:
            username = self.selected_user
        if not username:
            return
        self._select_user(username)
        self.receiver_entry.delete(0, tk.END)
        self.receiver_entry.insert(0, username)
        if username not in self.client.user_pubkeys:
            self.client._request_public_key(username)
        self.message_entry.focus()

    def verify_selected_user(self):
        username = self.selected_user
        if not username:
            return
        finger = self.client.get_user_fingerprint(username)
        if finger:
            self._show_user_fingerprint_dialog(username, finger)
            return

        with self.client.pending_manual_verifications_lock:
            if username in self.client.pending_manual_verifications:
                return
            self.client.pending_manual_verifications.add(username)
        self.append_chat("系统", f"正在获取 {username} 的公钥用于验证指纹...")
        self.client._request_public_key(username)

    def distrust_selected_user(self):
        username = self.selected_user
        if not username:
            return
        self.client.distrust_user(username)
        self._update_user_list(self._displayed_users)

    def copy_fingerprint(self):
        username = self.selected_user
        if not username:
            return
        finger = self.client.get_user_fingerprint(username)
        if finger:
            self.root.clipboard_clear()
            self.root.clipboard_append(finger)
            self.append_chat("系统", f"已复制 {username} 的指纹到剪贴板")

    # ------------------------------------------------------------------
    # 指纹对话框
    def _show_user_fingerprint_dialog(self, username, fingerprint):
        dlg = ctk.CTkToplevel(self.root)
        dlg.title("用户公钥验证")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("700x430")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=f"请与 {username} 核对以下指纹以确认身份:", wraplength=600, font=("", 11, "bold")).pack(pady=10)

        from src.common.crypto_utils import FingerprintWords
        try:
            words = FingerprintWords.fingerprint_to_words(fingerprint, 6)
            words_str = "  ".join(words).upper()
        except Exception:
            words = None
            words_str = "（无法生成单词）"

        word_frame = ctk.CTkFrame(dlg)
        word_frame.pack(pady=15, padx=20, fill=tk.X)
        ctk.CTkLabel(word_frame, text="指纹单词（6个）:", font=("", 10, "bold")).pack(anchor="w", pady=(0, 8))
        ctk.CTkLabel(word_frame, text=words_str, font=("", 16, "bold"), text_color=("#0066ff", "#6699ff")).pack(anchor="w", pady=10, padx=10)

        ctk.CTkLabel(dlg, text="请通过其他安全渠道（电话、当面）核对以上单词，以确认对方身份。", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=5)

        result = [False]

        def verify():
            result[0] = True
            dlg.destroy()

        def cancel():
            dlg.destroy()

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="验证通过", command=verify, width=120, corner_radius=8).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="取消", command=cancel, width=120, corner_radius=8).pack(side=tk.LEFT, padx=5)

        dlg.bind('<Escape>', lambda e: cancel())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)
        return result[0]

    def _show_own_fingerprint_dialog(self, title="我的指纹单词", display_name=None):
        if not self.client.id_pub:
            self._dialog_showerror("错误", "身份信息未就绪")
            return

        words = self.client.get_own_fingerprint_words(6)
        fingerprint = self.client._fingerprint_from_bytes(
            IdentityKeyManager.serialize_public_key(self.client.id_pub)
        )

        if not words:
            self._dialog_showerror("错误", "无法生成指纹单词")
            return

        dlg = ctk.CTkToplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        dlg.geometry("700x390")
        dlg.resizable(True, True)

        display_name = display_name or self.client.username or "当前账号"

        ctk.CTkLabel(dlg, text=f"您的身份指纹单词（{display_name}):", wraplength=600, font=("", 11, "bold")).pack(pady=10)

        word_frame = ctk.CTkFrame(dlg)
        word_frame.pack(pady=15, padx=20, fill=tk.X)
        ctk.CTkLabel(word_frame, text="指纹单词（6个）:", font=("", 10, "bold")).pack(anchor="w", pady=(0, 8))
        words_str = "  ".join(words).upper()
        ctk.CTkLabel(word_frame, text=words_str, font=("", 16, "bold"), text_color=("#0066ff", "#6699ff")).pack(anchor="w", pady=10, padx=10)

        ctk.CTkLabel(dlg, text="您可以将这些单词告诉他人，对方通过核对这些单词来确认您的身份。", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=5)
        ctk.CTkLabel(dlg, text="请通过其他安全渠道（电话、当面）分享这些单词。", wraplength=600, text_color=("orange", "orange"), font=("", 9)).pack(pady=(0, 10))

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(pady=15)
        ctk.CTkButton(btn_frame, text="确认", command=dlg.destroy, width=100, corner_radius=8).pack(side=tk.LEFT, padx=5)

        dlg.bind('<Escape>', lambda e: dlg.destroy())
        self.center_dialog(dlg)
        self.root.wait_window(dlg)

    def _show_own_fingerprint_after_register(self, username=None):
        self._show_own_fingerprint_dialog("我的指纹单词 - 请妥善保管", display_name=username)

    def _on_user_label_click(self, event):
        if self.client.id_pub:
            self._show_own_fingerprint_dialog(display_name=self.client.username)
        else:
            self._dialog_showinfo("提示", "身份信息未就绪")

    # ------------------------------------------------------------------
    # 托盘与退出
    def on_closing(self):
        self._quit_application()

    def on_window_unmap(self, event):
        if (not self.is_exiting and not self.is_minimized_to_tray and not self._tray_minimize_pending
                and self.root.state() == 'iconic'):
            self._tray_minimize_pending = True
            self.root.after(0, self.minimize_to_tray)

    def minimize_to_tray(self):
        self._tray_minimize_pending = False
        if pystray is None:
            self._quit_application()
            return
        if self.is_minimized_to_tray or self.tray_icon:
            return
        self.root.withdraw()
        self.is_minimized_to_tray = True
        image = Image.new('RGB', (64, 64), color=(30, 136, 229))
        draw = ImageDraw.Draw(image)
        draw.ellipse((10, 10, 54, 54), fill=(255, 255, 255))
        draw.ellipse((20, 20, 44, 44), fill=(30, 136, 229))
        menu = pystray.Menu(
            pystray.MenuItem('打开', lambda: self.root.after(0, self.restore_from_tray)),
            pystray.MenuItem('退出', lambda: self.root.after(0, self._quit_application))
        )
        self.tray_icon = pystray.Icon('kaleido', image, 'KaleidoTalk', menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def restore_from_tray(self):
        self._tray_minimize_pending = False
        self.is_minimized_to_tray = False
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None

    def _tray_notify(self, msg):
        if self.tray_icon:
            self.tray_icon.notify(msg[:100], "新消息")

    def _quit_application(self):
        self.is_exiting = True
        self._tray_minimize_pending = False
        self._close_context_menu()
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
        self.client.logout()
        try:
            self.update_button_states()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ----------------------------------------------------------------------
def main():
    app = ChatGUI()
    app.run()


if __name__ == '__main__':
    print("KaleidoTalk Copyright (C) 2026 Bangze Han")
    print("This program comes with ABSOLUTELY NO WARRANTY.")
    print("This is free software, and you are welcome to redistribute it")
    print("under the terms of the GNU General Public License version 3 or later.")
    main()
