#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
from urllib.parse import urlparse, quote_plus
from bs4 import BeautifulSoup
import gzip
import io

# --- 用户配置 ---
USERNAME = "2020021082"
PLAINTEXT_PASSWORD = "b881691214B" # 你的真实密码
EPORTAL_BASE_URL = "http://10.254.241.19/eportal/"
SERVICE_NAME = "电信" # 你确认手动选择此服务可成功

# --- 高级配置 ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
# 用于触发校园网关返回JS跳转代码的HTTP URL
CONNECTIVITY_TRIGGER_URL = "http://www.bilibili.com/" 
# 用于初始网络状态检查 和 登录成功后验证真实网络连通性的HTTPS URL
VERIFY_CONNECTIVITY_URL = "https://www.bilibili.com/" 

DEFAULT_PUB_EXPONENT = "10001"

# --- RSA 加密辅助函数 ---
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5
    import binascii
except ImportError:
    print("错误: 未找到 PyCryptodome 库。请安装: pip install pycryptodome")
    exit(1)

def rsa_encrypt(text_to_encrypt, n_hex, e_hex=DEFAULT_PUB_EXPONENT):
    reversed_text = text_to_encrypt[::-1]
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    key = RSA.construct((n, e))
    cipher = PKCS1_v1_5.new(key)
    encrypted_bytes = cipher.encrypt(reversed_text.encode('utf-8'))
    return binascii.hexlify(encrypted_bytes).decode('ascii')

def get_login_page_details(session, portal_base_url, connectivity_trigger_url): # 参数名保持不变
    print(f"步骤1: 访问 {connectivity_trigger_url} 获取JS跳转信息...")
    actual_login_page_url_from_js = None
    url_for_qs_and_referer = None
    query_string_from_url = None
    public_key_modulus = None
    public_key_exponent = DEFAULT_PUB_EXPONENT
    password_encrypt_setting = "false" 

    try:
        headers_for_trigger = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5', 'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1', 'Accept-Encoding': 'gzip, deflate'
        }
        # 第一次请求: 访问HTTP的 connectivity_trigger_url 以获取JS跳转代码
        response_js_redirect_page = session.get(connectivity_trigger_url, headers=headers_for_trigger, timeout=15, allow_redirects=True)
        print(f"  访问 {connectivity_trigger_url} 的响应状态码: {response_js_redirect_page.status_code}, 最终URL(可能已重定向): {response_js_redirect_page.url}")
        
        # 检查是否直接访问到了 connectivity_trigger_url 的最终目标 (例如 B站HTTPS页)
        # 如果是，说明网络可能已通，或者校园网未拦截这个HTTP请求
        # 但我们仍然主要依赖从其内容中提取JS跳转
        if "bilibili.com" in response_js_redirect_page.url.lower() and "哔哩哔哩" in response_js_redirect_page.text:
             if not re.search(r"""(?:top\.self|self|window|document|top)?\.location\.href\s*=\s*['"](http[^'"]+)['"]""", response_js_redirect_page.text, re.IGNORECASE):
                print("  在获取JS跳转步骤中，似乎已直接访问到目标检测点且未找到JS跳转，可能网络已通或初始检测逻辑需调整。")
                # 这种情况下，无法继续获取登录页，返回None表示失败
                return None, None, None, None, password_encrypt_setting


        redirect_match = re.search(r"""(?:top\.self|self|window|document|top)?\.location\.href\s*=\s*['"](http[^'"]+)['"]""", response_js_redirect_page.text, re.IGNORECASE)
        
        if redirect_match:
            actual_login_page_url_from_js = redirect_match.group(1)
            url_for_qs_and_referer = actual_login_page_url_from_js
            print(f"  从JS中提取到登录页URL: {url_for_qs_and_referer[:70]}...")
        else:
            print(f"  警告: 未在 {connectivity_trigger_url} 的响应中找到JS跳转代码。")
            # 如果没有JS跳转，并且也不是直接访问到了B站，那么尝试直接访问门户
            if not ("bilibili.com" in response_js_redirect_page.url.lower() and "哔哩哔哩" in response_js_redirect_page.text):
                print(f"  尝试直接访问门户基础URL: {portal_base_url}")
                response_portal_direct = session.get(portal_base_url, headers=headers_for_trigger, timeout=10, allow_redirects=True)
                url_for_qs_and_referer = response_portal_direct.url
            else:
                 print(f"  未找到JS跳转，但已直接访问到 {connectivity_trigger_url} 的最终目标。停止获取登录详情。")
                 return None, None, None, None, password_encrypt_setting
        
        if not url_for_qs_and_referer:
            print("  错误: 无法确定登录门户入口URL。")
            return None, None, None, None, password_encrypt_setting

        parsed_index_jsp_url = urlparse(url_for_qs_and_referer)
        if parsed_index_jsp_url.query:
            query_string_from_url = parsed_index_jsp_url.query
            print(f"  从登录页URL提取到原始queryString: {query_string_from_url[:60]}...")
        else:
            print(f"  警告: 未能从登录页URL提取queryString，pageInfo请求可能失败。")

        print(f"步骤2: 发送 pageInfo AJAX 请求获取密钥...")
        page_info_url = portal_base_url.rstrip('/') + "/InterFace.do?method=pageInfo"
        encoded_qs_for_pageinfo = quote_plus(query_string_from_url if query_string_from_url else "")
        page_info_data_str = f"queryString={encoded_qs_for_pageinfo}"
        
        ajax_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest', 'Referer': url_for_qs_and_referer,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        response_page_info = session.post(page_info_url, data=page_info_data_str.encode('utf-8'), headers=ajax_headers, timeout=10)
        response_page_info.raise_for_status()
        page_info_data = response_page_info.json()
        
        if page_info_data:
            public_key_modulus = page_info_data.get("publicKeyModulus")
            public_key_exponent = page_info_data.get("publicKeyExponent", DEFAULT_PUB_EXPONENT)
            if "passwordEncrypt" in page_info_data:
                password_encrypt_setting = str(page_info_data["passwordEncrypt"]).lower()
            print(f"  从pageInfo获取到 passwordEncrypt='{password_encrypt_setting}'")
            if public_key_modulus:
                 print(f"  获取到 publicKeyModulus: {public_key_modulus[:30]}...")
            elif password_encrypt_setting == "true":
                 print("  错误: pageInfo指示需加密但未提供publicKeyModulus!")
                 return None, None, query_string_from_url, url_for_qs_and_referer, password_encrypt_setting
        else:
            print("  错误: pageInfo AJAX响应为空或非JSON。")
            return None, None, query_string_from_url, url_for_qs_and_referer, password_encrypt_setting
        
        return public_key_modulus, public_key_exponent, query_string_from_url, url_for_qs_and_referer, password_encrypt_setting

    except Exception as e:
        print(f"  获取登录详情时发生错误: {e}")
        return None, None, None, None, password_encrypt_setting


def main():
    print("校园网自动登录脚本 (Python版)")
    print("-----------------------------------------")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    print("步骤A: 检查当前网络状态...")
    try:
        # 初始网络检查：访问 VERIFY_CONNECTIVITY_URL (HTTPS)
        # 如果这个HTTPS网址能直接访问成功，说明网络已通
        initial_check_response = session.get(VERIFY_CONNECTIVITY_URL, timeout=7, allow_redirects=True) # 允许重定向，尽管HTTPS B站一般不重定向到其他域
        
        is_connected = False
        if initial_check_response.status_code == 200:
            # 检查是否是B站HTTPS页面的特征内容
            if "bilibili.com" in initial_check_response.url.lower() and \
               ("https" in initial_check_response.url.lower()) and \
               ("<title>哔哩哔哩" in initial_check_response.text or "bilibili-player" in initial_check_response.text):
                is_connected = True
        elif initial_check_response.status_code == 204: # 某些HTTPS检测点可能返回204
            is_connected = True
        
        if is_connected:
            print(f"  网络已连接 (可访问 {VERIFY_CONNECTIVITY_URL})。退出脚本。")
            return
        else:
            print(f"  网络未通或需认证 (初始检查状态: {initial_check_response.status_code}, URL: {initial_check_response.url})。")
            # 如果访问 VERIFY_CONNECTIVITY_URL 失败，不代表一定是被校园网拦截返回JS
            # 因为HTTPS请求可能直接因网络不通而失败。
            # 所以，下面的 get_login_page_details 仍然使用 CONNECTIVITY_TRIGGER_URL (HTTP)

    except requests.exceptions.RequestException as e_initial_check:
        print(f"  网络未通 (初始检查请求 {VERIFY_CONNECTIVITY_URL} 时发生异常: {e_initial_check})。")
        # 即使这里异常，也继续尝试登录流程

    # 调用 get_login_page_details 时，使用 CONNECTIVITY_TRIGGER_URL (HTTP) 来获取JS跳转
    modulus, exponent, query_string, actual_login_url, password_encrypt_setting = get_login_page_details(session, EPORTAL_BASE_URL, CONNECTIVITY_TRIGGER_URL)
    
    # ... (后续的密码加密、POST登录、登录后验证逻辑与上一个版本基本一致) ...
    
    final_password_to_send = ""
    if password_encrypt_setting == "true":
        if not modulus:
            print("错误: 密码需加密但未获取到公钥模数。脚本终止。")
            exit(1)
        print("步骤B: 加密密码...")
        final_password_to_send = rsa_encrypt(PLAINTEXT_PASSWORD, modulus, exponent)
    else:
        print(f"步骤B: 根据服务器设置(passwordEncrypt='{password_encrypt_setting}'), 使用明文密码。")
        final_password_to_send = PLAINTEXT_PASSWORD
    
    if not query_string:
        print("警告: 未能获取queryString，登录可能失败。")

    post_data = {
        "userId": USERNAME, "password": final_password_to_send,
        "service": SERVICE_NAME, "queryString": query_string if query_string else "",
        "operatorPwd": "", "operatorUserId": "", "validcode": "",
        "passwordEncrypt": password_encrypt_setting
    }

    login_api_url = EPORTAL_BASE_URL.rstrip('/') + "/InterFace.do?method=login"
    print(f"步骤C: 尝试登录到 {login_api_url} ...")
    print(f"  使用服务: {SERVICE_NAME}, passwordEncrypt='{password_encrypt_setting}'")

    try:
        parsed_eportal_url = urlparse(EPORTAL_BASE_URL)
        origin = f"{parsed_eportal_url.scheme}://{parsed_eportal_url.netloc}"
        referer_url = actual_login_url if actual_login_url else EPORTAL_BASE_URL
        headers_login = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": referer_url, "Origin": origin
        }
        response = session.post(login_api_url, data=post_data, headers=headers_login, timeout=15)
        response.raise_for_status()
        
        login_successful = False
        server_message_decoded = ""
        try:
            json_resp = response.json()
            print(f"  登录响应JSON: {json_resp}")
            if json_resp.get("result") == "success":
                login_successful = True
            
            server_message_raw = json_resp.get("message", json_resp.get("msg", ""))
            if server_message_raw:
                try:
                    if isinstance(server_message_raw, str):
                        server_message_decoded = server_message_raw.encode('latin-1', errors='ignore').decode('gbk', errors='replace')
                    else:
                        server_message_decoded = str(server_message_raw)
                    print(f"  服务器消息: {server_message_decoded}")
                except Exception:
                    print(f"  服务器消息 (原始，解码失败): {server_message_raw}")
        except ValueError: 
            print(f"  登录响应不是JSON格式: {response.text[:200]}...")
            if '认证成功' in response.text and 'fail' not in response.text.lower(): login_successful = True

        if login_successful:
            print("步骤D: 登录成功!")
            try:
                print(f"  验证登录后网络，访问: {VERIFY_CONNECTIVITY_URL}")
                verify_conn = session.get(VERIFY_CONNECTIVITY_URL, timeout=7, allow_redirects=True) 
                final_verify_url = verify_conn.url
                print(f"  登录后网络检查，最终URL: {final_verify_url}, 状态码: {verify_conn.status_code}")

                is_truly_connected = False
                if verify_conn.status_code == 200:
                    if "bilibili.com" in final_verify_url.lower() and \
                       ("https" in final_verify_url.lower()) and \
                       ("<title>哔哩哔哩" in verify_conn.text or "bilibili-player" in verify_conn.text):
                        is_truly_connected = True
                
                if is_truly_connected:
                    print("  登录后网络连接已确认。")
                else:
                    print(f"  登录后网络检查未达预期。")
            except requests.exceptions.RequestException as e_verify:
                print(f"  登录后网络检查异常: {e_verify}")
        else:
            print("步骤D: 登录失败。")
            if not server_message_decoded : 
                 print(f"  请检查登录响应或之前的错误信息。")

    except requests.exceptions.HTTPError as e:
        print(f"登录过程中发生HTTP错误: {e.response.status_code} - {e}")
        if hasattr(e, 'response') and e.response: print(f"  响应内容: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"登录过程中发生网络错误: {e}")
    except Exception as e:
        print(f"登录POST请求过程中发生未知错误: {e}")

if __name__ == "__main__":
    main()