# agy-auth

`agy-auth` 是一个用于 Antigravity CLI (`agy`) 的多账号切换及凭据同步命令行工具。它直接对接本地的账号存储体系 (`~/.agy_auth`)。

---

## 1. 安装方法 

其它用户只需在安装了 Node.js / npm 的任何电脑上直接运行即可：

```bash
# 全局安装，支持 macOS、Windows、Linux
npm install -g agy-auth
```

或者使用 `npx` 临时免安装执行：

```bash
npx agy-auth list
```

---

## 2. 命令行参考 (CLI Subcommands)

* **列出所有已登录账号**：
  ```bash
  agy-auth list  # 或者 agy-auth ls
  ```

* **添加账号（支持浏览器登录）**：
  ```bash
  # 启动本地服务器捕获浏览器 OAuth 登录回调
  agy-auth add   # 或者 agy-auth login
  
  # 或者直接传入已有的 refresh_token 进行静默添加
  agy-auth add "<refresh_token>"
  ```

* **切换激活账户**：
  ```bash
  agy-auth switch <account_email_or_id> # 或者 agy-auth use <email_or_id>
  ```

* **查看当前激活的账号详情**：
  ```bash
  agy-auth current  # 或者 agy-auth whoami
  ```

* **删除账号**：
  ```bash
  agy-auth delete <account_email_or_id> # 或者 agy-auth remove <email_or_id>
  ```

