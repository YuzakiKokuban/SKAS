# SKAS (Skyland Auto Sign)

SKAS 是一个基于 Python 开发的轻量级森空岛（Skyland）自动签到工具。本项目专为 CI/CD 环境（如 GitHub Actions）设计，采用无状态架构，通过环境变量进行配置。

## 简介

本项目重构自 [FancyCabbage/skyland-auto-sign](https://gitee.com/FancyCabbage/skyland-auto-sign)，旨在提供更精简、易于维护且适合自动化部署的签到解决方案。

主要特性：

- **多游戏支持**：目前支持《明日方舟》(Arknights) 和《明日方舟·终末地》(Endfield)。
- **无状态设计**：不依赖本地文件存储 Token，完全基于内存和环境变量运行。
- **多账号支持**：支持配置多个鹰角网络通行证。
- **消息推送**：支持通用的 Webhook 推送签到结果。
- **安全风控适配**：内置设备指纹生成逻辑，适配森空岛 API 的验签机制。
