# SKAS (Skyland Auto Sign)

SKAS 是一个针对森空岛（Skyland）平台的轻量级自动化签到工具。当前版本已迁移为 Rust CLI，面向 CI/CD 场景设计，目标是提供稳定、无状态、便于自动部署的签到能力。

## 项目概述

项目通过模拟客户端请求，自动完成森空岛支持游戏的每日签到任务。整体设计坚持“配置即代码”，不依赖本地持久化存储，全部行为通过环境变量控制。

本项目重构自 [FancyCabbage/skyland-auto-sign](https://gitee.com/FancyCabbage/skyland-auto-sign)，当前仓库以 Rust 实现为主。

## 主要特性

* **Rust CLI**：主入口已迁移到 Rust，便于编译分发和在 CI 中直接运行。
* **多游戏支持**：当前支持《明日方舟》(Arknights) 与《明日方舟：终末地》(Endfield)。
* **风控适配**：内置 `security` 模块，完成 `dId`、`smid` 及设备指纹上报所需加密流程。
* **无状态架构**：通过 OAuth 2.0 授权码换取临时凭证，无需落地保存 Session。
* **多账户管理**：支持单个环境变量中配置多个鹰角通行证 Token。
* **消息推送**：支持钉钉、飞书及自定义 Webhook 形式的运行报告。

## 环境变量

| 变量名 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `SKYLAND_TOKEN` | String | (无) | **[敏感]** 用户认证 Token。多个账号使用英文逗号 `,` 分隔。 |
| `ENABLE_GAMES` | String | `arknights,endfield` | 指定要签到的游戏 `appCode`，以逗号分隔。 |
| `WEBHOOK_URL` | String | (无) | 可选。签到结果推送地址。 |

## 本地运行

请先安装 Rust 工具链。

1. 配置环境变量

   Linux/macOS:

   ```bash
   export SKYLAND_TOKEN="your_token_here"
   export ENABLE_GAMES="arknights,endfield"
   export WEBHOOK_URL=""
   ```

   Windows (PowerShell):

   ```powershell
   $env:SKYLAND_TOKEN="your_token_here"
   $env:ENABLE_GAMES="arknights,endfield"
   $env:WEBHOOK_URL=""
   ```

2. 启动程序

   ```bash
   cargo run
   ```

3. 编译发布版本

   ```bash
   cargo build --release
   ./target/release/skas
   ```

## GitHub Actions 部署

推荐将本仓库 Fork 后通过 GitHub Actions 定时执行。

1. 在仓库 `Settings -> Secrets and variables -> Actions` 中配置：

   | Secret 名称 | 必须 | 说明 |
   | :--- | :--- | :--- |
   | `SKYLAND_TOKEN` | 是 | 鹰角网络通行证 Token，多账号用逗号分隔。 |
   | `WEBHOOK_URL` | 否 | 结果通知地址。 |

2. 在 Workflow 中直接执行：

   ```bash
   cargo run --release
   ```

## 代码结构

* `src/main.rs`：CLI 入口，读取环境变量并串联整个流程。
* `src/client.rs`：登录、获取绑定角色、执行签到、生成签名头。
* `src/security.rs`：数美相关设备指纹生成、3DES/AES/RSA 加密与上报。
* `src/notifier.rs`：Webhook 推送。
## 技术细节

* **签名算法**：`sign` 请求头使用 HMAC-SHA256 + MD5 流程生成。
* **设备伪装**：`security` 模块实现 AES-CBC、3DES-ECB、RSA 公钥加密以及 gzip/base64 编码链路。
* **接口兼容**：保留 `SKYLAND_TOKEN`、`ENABLE_GAMES`、`WEBHOOK_URL` 这套原有环境变量接口，方便无缝替换。

## 许可证

本项目采用 [GNU General Public License v3.0 (GPLv3)](LICENSE) 许可证开源。

## 免责声明

1. 本项目仅供编程学习与技术交流使用，开发者不对使用后果负责。
2. 项目涉及接口与数据结构来源于客户端行为分析，不代表官方立场。
3. 自动化工具可能违反相关服务条款，请用户自行评估风险。
4. 请勿用于商业用途或大规模分发。
