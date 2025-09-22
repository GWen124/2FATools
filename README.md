# 2FATools

一个可部署到 GitHub Pages 的在线 2FA 工具，兼容 otpauth URI，界面风格参考 [2fa.run](https://2fa.run)。

## 本地预览

```bash
python3 -m http.server 8000
# 打开 http://localhost:8000
```

## 功能
- Base32 密钥与 `otpauth://` URI 解析
- TOTP 生成（SHA-1/SHA-256/SHA-512，可调位数/步长）
- 显示剩余时间进度条
- 生成 otpauth 二维码（前端离线）

## 部署到 GitHub Pages

1. 将本仓库推送到 GitHub，例如 `Wen/2FATools`。
2. 在 GitHub 仓库页面 → Settings → Pages：
   - Source 选择 `Deploy from a branch`
   - Branch 选择 `main` 和 `/ (root)`，保存。
3. 几分钟后访问 Pages 地址。

根目录包含 `.nojekyll`，避免 Jekyll 处理。
