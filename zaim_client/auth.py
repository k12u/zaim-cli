#!/usr/bin/env python3
"""
Zaim OAuth 1.0a 自動認証マネージャー
ローカルHTTPサーバーを使用してコールバック方式でトークンを自動取得
"""

import os
import json
import time
import secrets
import shutil
import subprocess
import sys
import webbrowser
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import socket

from requests_oauthlib import OAuth1Session
from requests import Session


class CallbackHandler(BaseHTTPRequestHandler):
    """OAuth コールバック用HTTPハンドラー"""
    
    def do_GET(self):
        """GET リクエストの処理"""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/callback':
            # OAuth コールバックの処理
            query_params = parse_qs(parsed_path.query)
            
            oauth_token = query_params.get('oauth_token', [None])[0]
            oauth_verifier = query_params.get('oauth_verifier', [None])[0]
            
            # サーバーインスタンスにパラメータを保存
            self.server.oauth_token = oauth_token
            self.server.oauth_verifier = oauth_verifier
            
            # レスポンスを送信
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            if oauth_token and oauth_verifier:
                html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Zaim CLI 認証完了</title>
                    <meta charset="utf-8">
                </head>
                <body>
                    <h1>✅ 認証が完了しました</h1>
                    <p>このタブを閉じて、ターミナルに戻ってください。</p>
                    <script>
                        setTimeout(() => window.close(), 3000);
                    </script>
                </body>
                </html>
                """
            else:
                html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Zaim CLI 認証エラー</title>
                    <meta charset="utf-8">
                </head>
                <body>
                    <h1>❌ 認証に失敗しました</h1>
                    <p>必要なパラメータが取得できませんでした。</p>
                </body>
                </html>
                """
            
            self.wfile.write(html.encode('utf-8'))
        else:
            # 404 レスポンス
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """ログメッセージを無効化（静寂モード）"""
        pass


class OAuthHTTPServer(HTTPServer):
    """OAuth コールバック用HTTPサーバー"""
    
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.oauth_token = None
        self.oauth_verifier = None
        self.timeout_occurred = False


class ZaimAuthManager:
    """Zaim OAuth 認証マネージャー"""
    
    def __init__(self, consumer_key: str, consumer_secret: str):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        
        # Zaim OAuth エンドポイント
        self.request_token_url = "https://api.zaim.net/v2/auth/request"
        self.authorize_url = "https://auth.zaim.net/users/auth"
        self.access_token_url = "https://api.zaim.net/v2/auth/access"
        self.verify_url = "https://api.zaim.net/v2/home/user/verify"
        
        # トークン保存ディレクトリ
        self.config_dir = Path.home() / '.zaim-cli'
        self.config_dir.mkdir(exist_ok=True, mode=0o700)
        self.token_file = self.config_dir / 'tokens.json'
    
    def find_free_port(self, start_port: int = 8000) -> int:
        """利用可能なポートを検索"""
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    return port
            except OSError:
                continue
        raise Exception("利用可能なポートが見つかりません")
    
    def get_request_token(self, callback_url: str) -> Tuple[str, str]:
        """リクエストトークンを取得"""
        oauth = OAuth1Session(
            client_key=self.consumer_key,
            client_secret=self.consumer_secret,
            callback_uri=callback_url
        )
        
        response = oauth.fetch_request_token(self.request_token_url)
        
        if not response.get('oauth_callback_confirmed') == 'true':
            raise Exception("OAuth callback が確認されませんでした")
        
        return response['oauth_token'], response['oauth_token_secret']
    
    def get_authorization_url(self, oauth_token: str) -> str:
        """認証URLを生成"""
        return f"{self.authorize_url}?oauth_token={oauth_token}"
    
    def get_access_token(self, oauth_token: str, oauth_token_secret: str, oauth_verifier: str) -> Tuple[str, str]:
        """アクセストークンを取得"""
        oauth = OAuth1Session(
            client_key=self.consumer_key,
            client_secret=self.consumer_secret,
            resource_owner_key=oauth_token,
            resource_owner_secret=oauth_token_secret,
            verifier=oauth_verifier
        )
        
        response = oauth.fetch_access_token(self.access_token_url)
        return response['oauth_token'], response['oauth_token_secret']
    
    def verify_token(self, access_token: str, access_token_secret: str) -> Dict[str, Any]:
        """トークンの有効性を検証してユーザー情報を取得"""
        oauth = OAuth1Session(
            client_key=self.consumer_key,
            client_secret=self.consumer_secret,
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret
        )
        
        response = oauth.get(self.verify_url)
        response.raise_for_status()
        return response.json()
    
    def save_tokens(self, access_token: str, access_token_secret: str, user_info: Dict[str, Any]):
        """トークンをファイルに保存"""
        token_data = {
            'access_token': access_token,
            'access_token_secret': access_token_secret,
            'user_info': user_info,
            'timestamp': int(time.time())
        }
        
        with open(self.token_file, 'w', encoding='utf-8') as f:
            json.dump(token_data, f, ensure_ascii=False, indent=2)
        
        # ファイル権限を600に設定（所有者のみ読み書き可能）
        self.token_file.chmod(0o600)
    
    def load_tokens(self) -> Optional[Dict[str, Any]]:
        """保存されたトークンを読み込み"""
        if not self.token_file.exists():
            return None
        
        try:
            with open(self.token_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
    
    def delete_tokens(self):
        """保存されたトークンを削除"""
        if self.token_file.exists():
            self.token_file.unlink()
    
    def open_browser(self, url: str) -> bool:
        """ブラウザでURLを開く"""
        if sys.platform.startswith('linux'):
            launchers = [
                'xdg-open',
                'wslview',
                'sensible-browser',
                'gnome-open',
                'kde-open5',
                'kde-open',
            ]

            for launcher in launchers:
                launcher_path = shutil.which(launcher)
                if not launcher_path:
                    continue

                try:
                    subprocess.run(
                        [launcher_path, url],
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    return True
                except (subprocess.CalledProcessError, OSError):
                    continue

        try:
            opened = webbrowser.open(url, new=2)
            if opened:
                return True
        except Exception:
            pass

        return False
    
    def login(self, port: Optional[int] = None, print_url: bool = False, timeout: int = 300) -> bool:
        """
        OAuth ログインを実行
        
        Args:
            port: 使用するポート番号（Noneの場合は自動選択）
            print_url: URLを出力するのみでブラウザを開かない
            timeout: タイムアウト秒数
            
        Returns:
            ログイン成功かどうか
        """
        try:
            # ポートを決定
            if port is None:
                port = self.find_free_port()
            
            callback_url = f"http://127.0.0.1:{port}/callback"
            
            print(f"OAuth 認証を開始します...")
            print(f"コールバックURL: {callback_url}")
            
            # 1. リクエストトークン取得
            print("1. リクエストトークンを取得中...")
            request_token, request_token_secret = self.get_request_token(callback_url)
            
            # 2. 認証URL生成
            auth_url = self.get_authorization_url(request_token)
            
            # 3. HTTPサーバー起動
            print(f"2. ローカルサーバーを開始中... (ポート: {port})")
            server = OAuthHTTPServer(('127.0.0.1', port), CallbackHandler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            
            # 4. ブラウザで認証URL を開く
            if print_url:
                print(f"以下のURLにアクセスして認証してください:")
                print(auth_url)
            else:
                print("3. ブラウザで認証ページを開いています...")
                if self.open_browser(auth_url):
                    print("ブラウザが開きました。認証を完了してください。")
                else:
                    print(f"ブラウザを自動で開けませんでした。以下のURLにアクセスしてください:")
                    print(auth_url)
            
            # 5. コールバック待ち
            print(f"4. 認証完了を待機中... (タイムアウト: {timeout}秒)")
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                if server.oauth_token and server.oauth_verifier:
                    break
                time.sleep(0.5)
            else:
                print("❌ タイムアウトしました。認証をやり直してください。")
                server.shutdown()
                return False
            
            # 6. トークン検証
            if server.oauth_token != request_token:
                print("❌ OAuth トークンが一致しません。")
                server.shutdown()
                return False
            
            # 7. アクセストークン取得
            print("5. アクセストークンを取得中...")
            access_token, access_token_secret = self.get_access_token(
                request_token, request_token_secret, server.oauth_verifier
            )
            
            # 8. トークン検証とユーザー情報取得
            print("6. トークンを検証中...")
            user_info = self.verify_token(access_token, access_token_secret)
            
            # 9. トークン保存
            print("7. トークンを保存中...")
            self.save_tokens(access_token, access_token_secret, user_info)
            
            # サーバー停止
            server.shutdown()
            
            print("✅ ログイン完了! トークンを保存しました。")
            print(f"ユーザー: {user_info.get('me', {}).get('name', '不明')} (ID: {user_info.get('me', {}).get('id', '不明')})")
            
            return True
            
        except Exception as e:
            print(f"❌ ログインエラー: {e}")
            return False
    
    def whoami(self) -> bool:
        """保存されたトークンでユーザー情報を表示"""
        tokens = self.load_tokens()
        if not tokens:
            print("❌ 保存されたトークンがありません。'login' コマンドを実行してください。")
            return False
        
        try:
            access_token = tokens['access_token']
            access_token_secret = tokens['access_token_secret']
            
            print("ユーザー情報を取得中...")
            user_info = self.verify_token(access_token, access_token_secret)
            
            # JSON出力
            print(json.dumps(user_info, ensure_ascii=False, indent=2))
            return True
            
        except Exception as e:
            print(f"❌ ユーザー情報取得エラー: {e}")
            print("トークンが無効になっている可能性があります。'login' コマンドでログインし直してください。")
            return False
    
    def logout(self) -> bool:
        """保存されたトークンを削除"""
        try:
            self.delete_tokens()
            print("✅ ログアウト完了。トークンを削除しました。")
            return True
        except Exception as e:
            print(f"❌ ログアウトエラー: {e}")
            return False
    
    def get_stored_credentials(self) -> Optional[Tuple[str, str]]:
        """保存されたアクセストークンを取得"""
        tokens = self.load_tokens()
        if not tokens:
            return None
        
        return tokens['access_token'], tokens['access_token_secret']


def main():
    """テスト用メイン関数"""
    import sys
    
    # 環境変数から認証情報を取得
    consumer_key = os.getenv('ZAIM_CONSUMER_KEY')
    consumer_secret = os.getenv('ZAIM_CONSUMER_SECRET')
    
    if not consumer_key or not consumer_secret:
        print("❌ ZAIM_CONSUMER_KEY と ZAIM_CONSUMER_SECRET 環境変数を設定してください")
        sys.exit(1)
    
    auth_manager = ZaimAuthManager(consumer_key, consumer_secret)
    
    if len(sys.argv) < 2:
        print("使用方法: python auth_manager.py <login|whoami|logout>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'login':
        success = auth_manager.login()
        sys.exit(0 if success else 1)
    elif command == 'whoami':
        success = auth_manager.whoami()
        sys.exit(0 if success else 1)
    elif command == 'logout':
        success = auth_manager.logout()
        sys.exit(0 if success else 1)
    else:
        print(f"❌ 不明なコマンド: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()