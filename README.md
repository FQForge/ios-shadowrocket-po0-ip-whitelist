# Shadowrocket 公网 IP 自动加白

Shadowrocket 在收到网络变更事件时检查一次公网 IP，连接期间也按每 5 分钟的计划检查。同一 Wi-Fi 或蜂窝网络下的出口 IP 变化由定时检查发现。首次发现地址或地址变化时，脚本会请求你的 HTTPS 加白接口。IPv4 和 IPv6 分别探测并记录。

模块、脚本和 Mock API 都是独立编写的。需求文档提供的参考仅用于了解 Shadowrocket 配置格式。实际防火墙规则由你配置的接口更新，Mock API 只维护内存中的名单。

## 发布到 GitHub

在电脑上使用 Node.js 20 或更新版本。准备一个你有权限推送的公开 GitHub 仓库，运行下面的命令，把 `OWNER/REPO` 替换为实际仓库名。

```sh
npm run prepare:import -- OWNER/REPO
```

该命令会更新模块中两处 JavaScript 的 Raw 地址，并生成本页的导入链接。提交这两处文件的改动后，将仓库推送到目标仓库的 `main` 分支。如果发布到其他分支或标签，在命令末尾传入对应名称。预览 Raw 模块和脚本，确认两个文件都能公开访问。GitHub 文件中只保留默认参数。

## 在 iPhone 上导入

<!-- import:start -->
发布前，下列地址中的 `OWNER/REPO` 是占位值。运行上一节的命令并推送仓库后，这里会显示对应的导入地址。

```text
https://raw.githubusercontent.com/OWNER/REPO/main/shadowrocket/public-ip-whitelist.srmodule
shadowrocket://install?module=https%3A%2F%2Fraw.githubusercontent.com%2FOWNER%2FREPO%2Fmain%2Fshadowrocket%2Fpublic-ip-whitelist.srmodule
```
<!-- import:end -->

1. 将 `shadowrocket://install?...` 导入地址粘贴到 iPhone 的 Safari 地址栏，确认打开 Shadowrocket。也可以在 Shadowrocket 里进入「配置 → 模块 → +」，粘贴 Raw 地址并下载。
2. 点击「公网 IP 自动加白」，打开「编辑参数」，填写下方的参数。当前版本的 Shadowrocket 支持这个入口。旧版本可以先更新，或在小火箭新建本地模块并手动替换两条 `argument` 里的 `{{{参数名}}}`。
3. 启用模块，将首页「全局路由」设为「配置」并连接。这样模块中的 `DIRECT` 规则可以让默认探测走手机当前网络。
4. 等待下一个 5 分钟刻度，或切换 Wi-Fi 与蜂窝网络。在脚本日志中查找 `[IP 加白]`，并在自己的接口上确认收到的地址。iPhone 只需 Shadowrocket，本模块无需开启 HTTPS 解密。

| 参数 | 默认值 | 填写方式 |
| --- | --- | --- |
| `api` | `unset` | 必填。输入完整的 HTTPS 地址，例如 `https://firewall.example.com/whitelist`。 |
| `method` | `POST` | 支持 `GET` 或 `POST`。 |
| `families` | `46` | `46` 同时检查两种地址，`4` 仅检查 IPv4，`6` 仅检查 IPv6。 |
| `token` | `unset` | 输入 Bearer 后面的值。接口无需鉴权时保留默认值。真实 Token 填在手机的模块参数中。 |
| `probe4` | `default` | 默认访问 `https://api.ipify.org/`，也可输入自己的 IPv4 HTTPS 探测地址。 |
| `probe6` | `default` | 默认访问 `https://api6.ipify.org/`，也可输入自己的 IPv6 HTTPS 探测地址。 |

自定义探测端点需返回单个对应地址族的公网 IP 纯文本。在配置中为自定义域名添加 `DOMAIN,域名,DIRECT` 规则，并确保域名按预期使用 IPv4 或 IPv6。URL 中的逗号、引号或竖线需要写成百分号编码。使用默认探测时，ipify 会接收到探测请求的出口 IP。加白用的 Token 只随加白请求发送。

4G 和 5G 之间的切换是否触发即时检查取决于 iOS 是否报告网络路径变化。锁屏、断开隧道或网络重连时，检查时间也由 iOS 和 Shadowrocket 调度。接口收到的是探测请求看到的出口 IP，请确认它和访问受保护服务时的出口一致。

## 加白接口约定

| 方法 | 示例请求 |
| --- | --- |
| `POST` | `Content-Type: application/json`，请求体 `{"ip":"8.8.4.4","family":4}` |
| `GET` | `/whitelist?ip=2606%3A4700%3A4700%3A%3A1111&family=6` |

`family` 为 `4` 或 `6`，两种地址分别发送请求。GET 会保留已有的查询参数，`ip` 和 `family` 由脚本填写。配置 Token 后会发送 `Authorization: Bearer <token>`。请使用证书有效、可直接访问的最终 HTTPS 地址。

服务端应在实际加白成功后返回 HTTP `2xx`，已存在的地址也可以直接返回成功。网络错误、超时、`408`、`429` 或 `5xx` 会在约 0.5 秒和 1 秒后最多重试两次。只有成功的地址才会记录，失败的地址下次会再检查。一种地址探测不到时，另一种仍可正常处理。服务端负责实际写入防火墙，以及管理旧记录的保留时间。现有服务若使用不同的参数名或鉴权格式，需要在接口前转换为上述约定。

## 在电脑上运行 Mock 测试

需要 Node.js 20 或更新版本和 OpenSSL。测试使用 Node.js 内置模块和临时证书，通过本地 HTTPS 发送请求。

```sh
npm test
```

测试在 Node.js 中模拟 Shadowrocket 的脚本接口，覆盖 IPv4 和 IPv6 的首次提交与变化检测、GET 和 POST、Bearer、重试及并发触发。模块导入、蜂窝切换事件、锁屏调度和真实防火墙写入尚未在 iPhone 上实测。

也可以单独启动 Mock API。

```sh
npm run mock
```

终端会显示监听地址和临时证书路径。把下面的 `CERT_PATH` 替换为输出的证书路径。

```sh
curl --cacert 'CERT_PATH' -H 'Authorization: Bearer mock-token' \
  'https://127.0.0.1:8443/whitelist?ip=8.8.4.4&family=4'
curl --cacert 'CERT_PATH' -H 'Authorization: Bearer mock-token' \
  'https://127.0.0.1:8443/state'
```

Mock 监听 `127.0.0.1`，`/ip4` 和 `/ip6` 会返回测试用地址。按 `Ctrl+C` 停止服务，名单随进程退出清空。

## 接口参考

- 模块导入、编辑参数及路由设置。 [Shadowrocket 社区使用手册](https://github.com/LOWERTOP/Shadowrocket#模块)
- 默认探测端点。 [ipify 文档](https://www.ipify.org/)
