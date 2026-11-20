# iOS 小火箭 po0 加白

导入模块后，只需填写 po0 防火墙 Token。Shadowrocket 在网络切换时和连接期间每 5 分钟请求一次加白。当前公网 IPv4 网段已在名单中时，po0 会保留原有记录。

模块、脚本和 Mock API 都是独立编写的。防火墙规则由 po0 的 HTTPS 接口更新，Mock API 维护测试用的内存名单。

## 发布到 GitHub

在电脑上使用 Node.js 20 或更新版本。准备一个你有权限推送的公开 GitHub 仓库，运行下面的命令，把 `OWNER/REPO` 替换为实际仓库名。

```sh
npm run prepare:import -- OWNER/REPO
```

该命令会更新模块中两处 JavaScript 的 Raw 地址，并生成本页的导入链接。提交这两处文件的改动后，将仓库推送到目标仓库的 `main` 分支。如果发布到其他分支或标签，在命令末尾传入对应名称。预览 Raw 模块和脚本，确认两个文件都能公开访问。GitHub 文件中只保留默认参数。

## 在 iPhone 上导入

<!-- import:start -->
Raw 地址可直接复制到小火箭的模块添加页面。[查看模块](https://raw.githubusercontent.com/FQForge/ios-shadowrocket-po0-ip-whitelist/main/shadowrocket/public-ip-whitelist.srmodule)

```text
https://raw.githubusercontent.com/FQForge/ios-shadowrocket-po0-ip-whitelist/main/shadowrocket/public-ip-whitelist.srmodule
```

也可以将下面的地址粘贴到 iPhone 的 Safari 地址栏，确认打开 Shadowrocket。

```text
shadowrocket://install?module=https%3A%2F%2Fraw.githubusercontent.com%2FFQForge%2Fios-shadowrocket-po0-ip-whitelist%2Fmain%2Fshadowrocket%2Fpublic-ip-whitelist.srmodule
```
<!-- import:end -->

1. 将 `shadowrocket://install?...` 导入地址粘贴到 iPhone 的 Safari 地址栏，确认打开 Shadowrocket。也可以在 Shadowrocket 里进入「配置 → 模块 → +」，粘贴 Raw 地址并下载。
2. 点击「iOS 小火箭 po0 加白」，打开「编辑参数」。在 `token` 一栏填入 po0 控制台机器详情页「防火墙」卡片上 `pgnfw_` 开头的完整 Token。接口地址和请求方式已配置好。已经导入过的用户先刷新模块。
3. 启用模块，将首页「全局路由」设为「配置」并连接。模块的 `DIRECT` 规则会让加白请求走手机当前网络。
4. 等待下一个 5 分钟刻度，或切换 Wi-Fi 与蜂窝网络。脚本日志出现 `[IP 加白] po0 已确认当前 IPv4 在白名单中` 后，可以到 po0 控制台核对名单。iPhone 只需 Shadowrocket，无需开启 HTTPS 解密。

真实 Token 填在手机的模块参数中。控制台显示的是完整加白 URL 时，复制 `/firewall/` 和 `/add` 之间的 `pgnfw_…`。

如果日志提示「小火箭未传入 Token」，在「配置 → 模块 → 新建模块」粘贴 Raw 模块的内容。在 `[Script]` 的两行中，把 `{{{token}}}` 换成同一个完整 Token。保存并启用这个本地模块即可。

4G 和 5G 之间的切换是否立即触发取决于 iOS 是否报告网络路径变化。锁屏、断开隧道或网络重连时，检查时间也由 iOS 和 Shadowrocket 调度。

## po0 加白接口

脚本直连 `https://124.221.69.228/api/firewall/<token>/add`，发送空请求体的 HTTPS `POST`。服务端从请求来源识别公网 IPv4，并以 `/24` 网段为单位加白。这个 po0 接口只支持 IPv4。

收到网络切换事件时，脚本立即发出加白请求。遇到网络错误、超时、`408`、`429` 或 `5xx` 时，网络切换触发的请求最多重试三次，定时触发的请求最多重试两次。服务端确认当前网段已在白名单中后，脚本才显示加白成功。

## 在电脑上运行 Mock 测试

需要 Node.js 20 或更新版本和 OpenSSL。测试使用 Node.js 内置模块和临时证书，通过本地 HTTPS 发送请求。

```sh
npm test
```

测试在 Node.js 中模拟 Shadowrocket 和 po0 接口，覆盖单 Token 导入、自动加白、重复请求、出口变化和重试。脚本原有的自定义接口也通过本地 HTTPS 测试，覆盖 IPv4、IPv6 和 Bearer。模块导入、蜂窝切换事件、锁屏调度和真实防火墙写入尚未在 iPhone 上实测。

也可以单独启动用于自定义接口的 Mock API。

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
- po0 接口格式和 IPv4 网段规则。 [po0 防火墙接口参考](https://github.com/w0ven/po0fw#原理)
