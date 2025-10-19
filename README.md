# Eportal 校园网自动登录脚本 (Python)

这是一个用于部分使用特定版本 Eportal 认证系统的校园网自动登录的 Python 脚本。
它支持通过客户端 JavaScript 跳转获取登录页面、模拟 AJAX 请求获取 RSA 公钥、并进行 RSA 加密登录的认证流程。

## 特性

*   自动检测网络连通性，如果已连接则跳过登录。
*   模拟浏览器行为，访问指定 HTTP URL 以触发认证网关返回包含 JavaScript 跳转的页面。
*   从 JavaScript 跳转代码中提取实际登录页 URL。
*   模拟 AJAX (`pageInfo`) 请求从服务器动态获取 RSA 公钥（Modulus 和 Exponent）。
*   根据服务器返回的配置动态决定是否对密码进行 RSA 加密。
*   支持密码的 RSA 加密（反转后加密，PKCS#1 v1.5 填充）。
*   登录成功后再次验证网络连通性。

## 免责声明

*   **本脚本仅供学习和研究使用，请勿用于非法用途。**
*   **请务必确保你有权访问和自动化登录你所在学校的网络。**
*   **脚本的有效性高度依赖于特定校园网 Eportal 系统的版本和配置。不同学校、不同时期，认证流程和页面结构可能存在差异，脚本可能需要相应调整才能工作。**
*   **请自行承担使用本脚本可能带来的一切风险。开发者不对任何因使用本脚本造成的直接或间接损失负责。**
*   **请勿将你的真实密码硬编码到公开发布的脚本中。如果需要共享，请使用占位符或配置文件。**

## 环境要求

*   Python 3.x
*   `requests` 库: 用于发送 HTTP 请求。
*   `BeautifulSoup4` 库: 用于解析 HTML (虽然当前版本主要依赖正则和 AJAX JSON 解析，但保留以备后续可能需要)。
*   `pycryptodome` 库: 用于 RSA 加密。

你可以使用 pip 安装所需库：
```bash
pip install requests beautifulsoup4 pycryptodome
```

## 配置

在运行脚本之前，你需要修改脚本文件 (`auth.py` 或你保存的文件名) 开头的以下配置项：

```python
# --- 用户配置 ---
USERNAME = "你的学号"  # 将引号内的内容替换为你的真实学号
PLAINTEXT_PASSWORD = "你的明文密码"  # 将引号内的内容替换为你的真实密码
EPORTAL_BASE_URL = "http://你的认证服务器IP或域名/eportal/" # 例如: "http://10.0.0.55/eportal/"，必须以 / 结尾
SERVICE_NAME = "你登录时选择的服务名称" # 例如: "电信", "校园网", "移动" 等，需与认证页面完全一致

# --- 高级配置 (通常不需要修改，但可以根据实际情况调整) ---
# 用于触发校园网关返回JS跳转代码的HTTP URL
CONNECTIVITY_TRIGGER_URL = "http://www.baidu.com/" 
# 用于初始网络状态检查 和 登录成功后验证真实网络连通性的HTTPS URL
VERIFY_CONNECTIVITY_URL = "https://www.baidu.com/" 
```

**重要提示：**
*   `EPORTAL_BASE_URL`：这个通常是你在浏览器中看到的认证页面的基础路径，例如 `http://10.254.241.19/eportal/`。**末尾的 `/` 非常重要。**
*   `SERVICE_NAME`：这个参数**非常关键**。你需要确保它与你手动登录校园网时，在登录页面上看到的或选择的“服务提供商”（如 电信、移动、联通、校园网/教育网）的名称**完全一致**。如果名称不匹配，即使账号密码正确，也可能导致登录失败。你可以通过脚本成功获取 `pageInfo` AJAX 响应后，从打印的 JSON 数据中查看可用的服务名称及其默认设置。
*   `CONNECTIVITY_TRIGGER_URL`：这是一个普通的 HTTP 网址。当网络未认证时，访问它会被校园网认证系统拦截并返回一个包含 JavaScript 跳转指令的页面，该指令会将浏览器重定向到真正的校园网登录页。你可以选择一个响应速度快且稳定的 HTTP 网址。
*   `VERIFY_CONNECTIVITY_URL`：这是一个 HTTPS 网址，用于在脚本开始时和登录成功后检查真实的互联网连通性。

## 如何运行

1.  确保已安装 Python 和所需的库。
2.  根据上面的说明修改脚本中的用户配置。
3.  在终端或命令行中运行脚本：
    ```bash
    python auth.py
    ```

脚本会输出详细的执行步骤和结果。

## 调试

如果脚本运行失败，请仔细阅读输出的错误信息。以下是一些常见的调试点：

1.  **配置错误**：检查 `USERNAME`, `PLAINTEXT_PASSWORD`, `EPORTAL_BASE_URL`, `SERVICE_NAME` 是否完全正确。
2.  **JS 跳转提取失败**：`CONNECTIVITY_TRIGGER_URL` 可能没有按预期返回包含 JS 跳转的页面。尝试更换其他 HTTP 网址。
3.  **`pageInfo` AJAX 请求失败**：
    *   检查 `EPORTAL_BASE_URL` 是否正确。
    *   检查从登录页 URL 中提取的 `queryString` 是否正确。
    *   `pageInfo` 接口的 URL (`/InterFace.do?method=pageInfo`) 是否与你的学校系统一致。
4.  **RSA 公钥获取失败**：`pageInfo` 响应中可能没有 `publicKeyModulus` 或 `publicKeyExponent` 字段，或者字段名不同。
5.  **`passwordEncrypt` 参数值问题**：脚本现在会从 `pageInfo` 动态获取这个值。如果服务器行为与此不符，可能需要调整。
6.  **登录失败（用户名或密码错误）**：
    *   **首要检查**：你的明文密码和学号是否100%正确。
    *   **其次检查**：`SERVICE_NAME` 是否与认证页面完全匹配。
    *   最后才考虑更复杂的编码或加密细节问题。
7.  **编码问题**：如果输出的服务器消息是乱码，脚本中尝试了 GBK 解码，但可能需要根据实际情况调整。
8.  **Gzip 解压**：脚本已加入 Gzip 手动解压逻辑，以应对服务器发送压缩内容但未正确声明 `Content-Encoding` 的情况。

你可以取消脚本中 `get_login_page_details` 函数内一些被注释掉的 `print` 语句（例如打印完整的 `pageInfo` JSON，或将解码后的 HTML 保存到文件）来获取更详细的调试信息。

## 贡献

欢迎提交 Pull Requests 或 Issues 来改进此脚本。如果你发现脚本在你的学校网络中工作不正常，请提供尽可能详细的错误信息、你的 Eportal 系统版本（如果知道的话）以及相关的（已脱敏的）网络请求和响应数据，以便分析和修复。

