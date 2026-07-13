# Upstream Ratio Watch

一个用于监控上游 AI 服务分组倍率和账户余额的轻量级 Web 管理面板。

当前支持 NewAPI 兼容站点和 sub2api 站点，后续可以继续扩展其他上游类型。项目适合少量上游站点的日常监控，不包含批量注册、账号批量操作等功能。

## 功能

- 手动添加 NewAPI / sub2api 站点
- NewAPI 定时采集 `GET /api/user/groups`
- sub2api 支持普通用户账号登录，也支持导入浏览器登录态采集用户可见分组
- 支持 NewAPI 系统访问令牌和 `New-Api-User` 获取认证后可见分组
- 监控分组倍率变化、新增分组、删除分组、描述变化
- 每个站点可指定实际接入的分组，仅推送这些分组的变化
- 监控 sub2api 分组状态、专属属性、订阅类型、RPM 限制变化
- 采集 NewAPI `/api/user/self` 与 sub2api `/api/v1/user/profile` 的账户余额
- 支持每站点设置低余额阈值，跌破与恢复时分别通知一次
- 展示隐藏分组和认证后新增分组
- 使用 SQLite 保存倍率、余额快照和变化记录
- 支持飞书、企业微信、SMTP 邮箱推送改价与余额提醒
- 内置登录保护，页面和业务 API 均需登录，会话默认有效 30 天
- Python 标准库后端，静态 HTML/CSS/JS 前端

## Docker 部署

推荐使用 Docker 部署，适合放在 VPS、云服务器、NAS 或 1Panel / 宝塔这类面板里长期运行。

完整部署命令：

```bash
git clone https://github.com/Regert888/upstream-ratio-watch.git
cd upstream-ratio-watch
docker compose up -d
```

然后访问：

```text
http://服务器IP:8000
```

查看日志：

```bash
docker compose logs -f
```

停止服务：

```bash
docker compose down
```

更新项目：

```bash
cd upstream-ratio-watch
git pull
docker compose up -d --build
```

如果服务器已经占用 8000 端口，可以修改 `docker-compose.yml`，把：

```yaml
- "8000:8000"
```

改成：

```yaml
- "18000:8000"
```

然后访问：

```text
http://服务器IP:18000
```

运行数据会保存在项目目录下的 `data/`：

```text
./data:/app/data
```

这里会保存 SQLite 数据库、登录配置、站点配置、系统访问令牌、SMTP 配置和监控历史。升级或重建容器前，请保留这个目录。

默认时区是北京时间：

```yaml
TZ: Asia/Shanghai
APP_TIMEZONE: Asia/Shanghai
```

`APP_TIMEZONE` 用于控制监控记录和推送消息里的时间显示。如果部署在其他时区，可以在 `docker-compose.yml` 里改成对应的 IANA 时区名称。

## 本地启动

```bash
python app.py
```

打开浏览器访问：

```text
http://127.0.0.1:8000
```

本地默认监听 `127.0.0.1:8000`。如果需要指定监听地址或端口，可以设置环境变量：

```bash
HOST=0.0.0.0 PORT=8000 python app.py
```

## 登录配置

首次启动时，程序会自动创建 `data/auth.json`。默认用户名为 `admin`，初始密码和会话签名密钥均为随机生成，请直接打开该文件查看并修改：

```json
{
  "username": "admin",
  "password": "your-strong-password",
  "session_days": 30,
  "session_secret": "保留自动生成值"
}
```

- `username` 和 `password` 可直接修改，无需改代码或重建镜像；下一次请求会读取最新配置。
- 修改用户名或密码后，之前签发的登录状态会立即失效，需要重新登录。
- `session_days` 控制登录有效天数，默认 30 天，可设置为 1 到 365。
- `session_secret` 用于签名登录 Cookie，请保留自动生成的随机值，不要公开或与他人共用。
- `data/` 已被 Git 忽略；Docker 部署已挂载该目录，因此重建容器不会丢失登录配置。

## 添加站点

在 Web UI 点击“添加站点”，填写：

- 站点名称：自定义名称，方便自己识别。
- 平台类型：选择 NewAPI 或 sub2api。
- Base URL：上游站点地址，例如 `https://example.com`，不要带具体 API 路径。
- 监控间隔：单位为分钟，最低 1 分钟。
- 启用监控：开启后会按设定间隔自动检测。

保存后，程序会定时访问：

```text
GET {Base URL}/api/user/groups
```

这个接口通常不需要登录，可以看到公开分组和公开倍率。

## sub2api 监控

sub2api 普通用户不能拿到上游管理员 API Key，所以本项目使用普通用户账号登录后读取该账号可见的分组。

添加 sub2api 站点时填写：

- 平台类型：sub2api
- Base URL：sub2api 站点地址，例如 `https://example.com`
- 认证方式：账号密码登录，或导入登录态

检测时会请求：

```text
POST {Base URL}/api/v1/auth/login
GET {Base URL}/api/v1/groups/available
GET {Base URL}/api/v1/groups/rates
```

其中：

- `/groups/available` 返回该普通用户可以绑定和使用的分组。
- `/groups/rates` 返回该普通用户的专属分组倍率。

如果某个分组存在用户专属倍率，本项目会优先按用户专属倍率监控。

### 方式一：账号密码登录

适合没有开启 Turnstile，或者没有额外 Cloudflare 拦截的 sub2api 站点。

填写：

- 用户邮箱：上游 sub2api 的普通用户邮箱
- 用户密码：该普通用户密码

保存后，程序会定时用该账号登录，并读取该账号可见的分组和专属倍率。

### 方式二：导入登录态

适合开启 Turnstile 的 sub2api 站点。你先在浏览器里正常登录一次，再把浏览器保存的登录态导入本项目。

操作步骤：

1. 用浏览器打开上游 sub2api 站点。
2. 正常输入账号密码登录，并按页面要求完成人机验证。
3. 登录成功后按 `F12` 打开开发者工具。
4. 找到 `Application` / `应用程序`。
5. 找到 `Local Storage` / `localStorage（本地存储）`。
6. 选择当前 sub2api 站点域名。
7. 复制下面这些值，填入本项目的“导入登录态”表单：

```text
auth_token
refresh_token
token_expires_at
```

字段说明：

- `auth_token`：必填，监控程序访问 sub2api 用户分组接口时使用。
- `refresh_token`：建议填写，`auth_token` 过期后程序会尝试自动刷新。
- `token_expires_at`：可选，浏览器记录的 token 过期时间，主要用于记录和后续展示。

注意：

- 导入登录态不是绕过 Turnstile，而是复用你已经在浏览器里合法登录后的状态。
- 如果上游 Cloudflare 直接拦截服务器请求，例如返回 `Error 1010 browser_signature_banned`，即使导入登录态也可能无法采集，因为请求还没到 sub2api 后端接口。
- 编辑站点时，如果不想修改 `auth_token` 或 `refresh_token`，对应输入框可以留空。

## 认证增强监控

有些 NewAPI 站点存在“用户专属分组”或“隐藏分组”。这些分组不会出现在公开的 `/api/user/groups` 里，只有带上系统访问令牌和用户 ID 后才能看到。

如果需要监控这类分组，在添加或编辑站点时开启“认证增强监控”，并填写：

- 系统访问令牌
- NewAPI 用户 ID

认证增强监控会额外请求：

```text
GET {Base URL}/api/user/self/groups
GET {Base URL}/api/user/groups
```

请求头会带上：

```text
Authorization: 系统访问令牌
New-Api-User: NewAPI 用户 ID
```

### 系统访问令牌怎么获取

在 NewAPI 个人设置中获取：

1. 登录 NewAPI。
2. 进入「个人设置」。
3. 进入「账户管理」。
4. 进入「安全设置」。
5. 找到「系统访问令牌」。
6. 复制该令牌，填入本项目的“系统访问令牌”。

不同 NewAPI 前端版本的菜单名称可能略有差异，但一般路径是：

```text
个人设置 → 账户管理 → 安全设置 → 系统访问令牌
```

该令牌可以是管理员或用户自己的访问令牌，用于让监控程序按指定用户身份读取可见分组。

注意：

- 不要填写普通中转 API Key。
- 不要填写用户生成的模型调用 Key。
- 这里需要的是 NewAPI 页面里显示的“系统访问令牌”。

### NewAPI 用户 ID 怎么获取

用户 ID 是该账号在上游 NewAPI 站点里的数字 ID，用来指定要查看哪个用户可见的分组。

常见获取方式：

1. 登录上游 NewAPI 站点后台。
2. 进入用户管理。
3. 将这个数字填入“NewAPI 用户 ID”。

例如在上游的 ID 是 `4`，就填写：

```text
4
```

不要填写邮箱、用户名或用户 API Key，这里只填写在上游的用户 ID。

### 什么时候需要开启认证增强

建议在这些情况下开启：

- 上游站点有 VIP 分组、专属分组或隐藏分组。
- 公开接口只能看到默认分组，但账号实际还能使用更多分组。
- 需要监控某个账号可见的真实分组倍率。

如果只需要监控公开分组，可以不开启认证增强。

### 常见问题

如果认证增强没有看到隐藏分组，优先检查：

- 系统访问令牌是否正确。
- `New-Api-User` 是否填写的是用户数字 ID。
- 该用户是否真的拥有专属分组。
- 该 NewAPI 站点是否支持 `/api/user/self/groups`。
- 站点是否限制了系统访问令牌权限。


## 邮箱推送

在 Web UI 的“消息推送”页面配置 SMTP：

- SMTP 服务器
- 端口
- 邮箱账号
- 邮箱授权码或密码
- 发件人
- 收件人
- SSL 开关

当检测到倍率、分组或余额预警变化时，会自动发送邮件提醒。

## 余额监控

在添加或编辑站点时可启用“低余额预警”，并按美元设置阈值。

- NewAPI：需要开启认证增强监控，程序请求 `GET /api/user/self`，将返回的 `quota` 按站点 `quota_per_unit` 换算为美元。
- sub2api：复用账号登录或导入的登录态，请求 `GET /api/v1/user/profile`，读取返回的 `balance`。
- 首次检测到余额小于或等于阈值时发送低余额通知；余额持续偏低时不会重复发送。
- 余额恢复到阈值之上时发送恢复通知，并允许下一次跌破时再次预警。

如果某个兼容站点修改或禁用了上述用户接口，页面会显示余额采集错误，但原有倍率采集仍会继续工作。

## 指定分组通知

在“站点详情”或编辑站点弹窗中勾选实际接入的分组并保存。首次配置时默认勾选当前全部分组；你只需取消不需要通知的分组。程序仍会采集并记录全部分组变化，但飞书、企业微信和邮件只会推送所选分组的倍率、删除、状态等变化。余额预警不受该范围影响。

旧站点和未修改通知范围的站点默认通知全部分组。分组使用完整名称精确匹配。

## 飞书推送

在飞书群中添加自定义机器人，然后在“消息推送”页面填写：

- 启用飞书推送
- 机器人 Webhook
- 签名密钥（机器人启用签名校验时填写）

保存后可点击“测试飞书”。倍率上涨/下降、分组变化、低余额和余额恢复都会发送到飞书群。

## 企业微信推送

在 Web UI 的“消息推送”页面配置企业微信群机器人：

- 启用企业微信推送
- 填写企业微信群机器人 Webhook

消息会以 Markdown 形式发送到对应群聊，不需要服务器回调，也不需要额外公网地址。

常见格式：

```text
https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxx
```

如果 Webhook 填写正确，点击“测试企业微信”即可发送测试消息。

## 说明

- 默认监控间隔：3 分钟
- 最低监控间隔：1 分钟
- 当前适配器：NewAPI / sub2api 分组倍率与用户余额监控
