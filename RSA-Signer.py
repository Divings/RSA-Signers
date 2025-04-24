
# Copyright (c) 2025 Innovation Craft Inc. All Rights Reserved.
# 本ソフトウェアはプロプライエタリライセンスに基づき提供されています。

# rsa_signer_gui.py

import base64
import configparser
import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import sys

def show_info(title, message):
    messagebox.showinfo(title, message)

def show_error(title, message):
    messagebox.showerror(title, message)

def generate_keys(private_key_path=None, public_key_path=None):
    try:
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        key_dir = os.path.join(base_dir, "Key")
        if private_key_path is None:
            private_key_path = os.path.join(key_dir, "private.pem")
        if public_key_path is None:
            public_key_path = os.path.join(key_dir, "public.pem")
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
            show_info("ディレクトリ作成", f"鍵ディレクトリを作成しました：\n{key_dir}")
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            key = RSA.generate(2048)
            with open(private_key_path, "wb") as f:
                f.write(key.export_key())
            with open(public_key_path, "wb") as f:
                f.write(key.publickey().export_key())
            show_info("鍵生成", f"🔐 鍵ペアを生成しました。\n\n秘密鍵: {private_key_path}\n公開鍵: {public_key_path}")
    except Exception as e:
        show_error("エラー", f"鍵生成中にエラーが発生しました。\n{e}")

def get_signature_filename(file_path: str) -> str:
    return file_path + ".sig"

def sign_file(file_path: str, private_key_path: str = None):
    try:
        if private_key_path is None:
            base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            private_key_path = os.path.join(base_dir, "Key", "private.pem")
        signature_path = get_signature_filename(file_path)
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())
        with open(file_path, "rb") as f:
            file_data = f.read()
        hash_obj = SHA256.new(file_data)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        with open(signature_path, "wb") as f:
            f.write(base64.b64encode(signature))
        show_info("署名成功", f"✅ 署名を保存しました。\n\nファイル: {signature_path}")
    except Exception as e:
        show_error("署名エラー", f"署名作成中にエラーが発生しました。\n{e}")

def verify_file_signature(file_path: str, public_key_path: str = None):
    try:
        if public_key_path is None:
            base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            public_key_path = os.path.join(base_dir, "Key", "public.pem")
        signature_path = get_signature_filename(file_path)
        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        with open(file_path, "rb") as f:
            file_data = f.read()
        with open(signature_path, "rb") as f:
            signature_b64 = f.read()
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            show_error("署名エラー", "Base64デコード失敗：署名ファイルが破損しています。")
            return
        hash_obj = SHA256.new(file_data)
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        show_info("検証成功", "検証成功：署名とファイルは一致しています。")
    except (ValueError, TypeError):
        show_error("検証失敗", "署名が改ざんされているか、ファイルが変更されています。")
    except Exception as e:
        show_error("検証エラー", f"検証中にエラーが発生しました。\n{e}")

# ===== GUI部分 =====
def launch_gui():
    root = tk.Tk()
    root.title("RSA 署名ツール")
    root.geometry("400x200")
        # アイコン設定 (icoファイルが存在する場合)
    try:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "ico.ico")
        root.iconbitmap(icon_path)
    except Exception as e:
        pass

    tk.Label(root, text="RSA署名ユーティリティ", font=("Arial", 14)).pack(pady=10)

    def select_file_and_sign():
        file_path = filedialog.askopenfilename()
        if file_path:
            sign_file(file_path)

    def select_file_and_verify():
        file_path = filedialog.askopenfilename()
        if file_path:
            verify_file_signature(file_path)

    tk.Button(root, text="🔐 鍵ペア生成", command=generate_keys, width=30).pack(pady=5)
    tk.Button(root, text="🖋 ファイルに署名", command=select_file_and_sign, width=30).pack(pady=5)
    tk.Button(root, text="🔎 署名を検証", command=select_file_and_verify, width=30).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    launch_gui()
