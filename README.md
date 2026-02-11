# SKAS (Skyland Auto Sign)

SKAS 是一个针对森空岛（Skyland）平台的轻量级自动化签到工具。本项目基于 Python 开发，专为 CI/CD 环境（如 GitHub Actions）设计，旨在提供稳定、无状态且具备一定风控规避能力的签到解决方案。

## 项目概述

本项目通过模拟客户端网络请求，自动完成森空岛支持游戏的每日签到任务。其核心设计理念为“配置即代码”，不依赖本地持久化存储，完全通过环境变量控制运行逻辑。
本项目重构自 [FancyCabbage/skyland-auto-sign](https://gitee.com/FancyCabbage/skyland-auto-sign)，旨在提供更精简、易于维护且适合自动化部署的签到解决方案。

### 主要特性

* **多游戏支持**：目前完整支持《明日方舟》(Arknights) 与《明日方舟：终末地》(Endfield)。
* **风控适配**：内置 `security` 模块，实现了基于数美（ShuMei）协议的设备指纹生成与上报逻辑，能够动态生成合法的 `dId` 和 `smid`，确保存取凭证（Cred）获取过程的有效性。
* **无状态架构**：通过 OAuth 2.0 授权码机制动态获取临时凭证，无需在本地保存过期的 Session 或 Cookies。
* **多账户管理**：支持通过单一环境变量配置多个鹰角网络通行证。
* **消息推送**：集成了通用的 Webhook 通知接口，支持钉钉、飞书及自定义 HTTP 服务端推送运行报告。

## 部署指南

本项目推荐使用 GitHub Actions 进行自动化部署。

### GitHub Actions 配置

1. **Fork 本仓库**：将本项目 Fork 至您的 GitHub 账号下。
2. **配置 Secrets**：在仓库的 `Settings` -> `Secrets and variables` -> `Actions` 中添加以下 Repository secrets：

    | Secret 名称 | 必须 | 说明 |
    | :--- | :--- | :--- |
    | `SKYLAND_TOKEN` | 是 | 鹰角网络通行证 Token。支持多账号，使用英文逗号 `,` 分隔。 |
    | `WEBHOOK_URL` | 否 | 签到结果推送地址（支持钉钉、飞书 Webhook）。 |

3. **启用 Workflow**：进入 `Actions` 页面，启用 `SKAS Auto Sign` 工作流。
4. **执行计划**：默认配置下，任务将于每日 UTC 时间 01:00（北京时间 09:00）自动执行。

### 环境变量说明

| 变量名 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `SKYLAND_TOKEN` | String | (无) | **[敏感]** 用户的认证 Token。获取方式请自行抓包或参考相关文档。 |
| `ENABLE_GAMES` | String | `arknights,endfield` | 指定需要签到的游戏 `appCode`，以逗号分隔。 |
| `WEBHOOK_URL` | String | (无) | 接收 JSON 格式推送的 Webhook 地址。 |

## 本地开发与运行

如需在本地环境进行调试或二次开发，请确保 Python 版本 >= 3.10。

1. **安装依赖**

    ```bash
    pip install -r requirements.txt
    ```

2. **配置环境变量**
    Windows (PowerShell):

    ```powershell
    $env:SKYLAND_TOKEN="your_token_here"
    ```

    Linux/macOS:

    ```bash
    export SKYLAND_TOKEN="your_token_here"
    ```

3. **运行入口**

    ```bash
    python src/main.py
    ```

## 技术细节

* **签名算法**：请求头中的 `sign` 字段通过 HMAC-SHA256 算法生成，结合时间戳与请求路径确保请求完整性。
* **设备伪装**：`src/security.py` 包含了一套完整的加密流程（涉及 AES-CBC, 3DES, RSA），用于向风控端点生成并上报虚拟化的浏览器环境参数。

## 许可证

本项目采用 [GNU General Public License v3.0 (GPLv3)](LICENSE) 许可证开源。

## 免责声明

1. 本项目仅供计算机编程学习与技术交流使用，开发者不对使用本项目产生的任何后果负责。
2. 本项目涉及的 API 接口与数据结构均来源于对客户端的分析，不代表官方行为。
3. 使用自动化工具可能违反游戏服务条款（ToS），请用户自行评估风险。
4. 请勿将本项目用于商业用途或大规模分发。
