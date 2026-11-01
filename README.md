# whatsapp-e2ee

Python WhatsApp 普通单聊、群聊和媒体端到端加解密工程，使用 `pyproject.toml`、SQLite 和两个现有协议库。包含消息封装、设备目录、密钥分发、持久投递、协议重试、媒体任务与可恢复下载；网络传输由显式适配器提供。

所有测试使用合成端点、历史原引擎夹具、独立算法向量或内存传输。真机、真实聊天发送、媒体上传及服务端接受验证由用户另行决定；本工程不重新实现或审查 Noise。

真实收发适配层、手机状态导入工具、受控实测 runner 及其专用测试统一放在根目录 `local-integration/`。账户快照、凭据、实发计划与确认记录、运行日志和抓取结果也放在此目录。该目录整体由 Git 忽略，并从源码分发包排除；这些代码和资料不提交到 Git。`src/` 保留可注入传输的通用协议接口，`tests/` 与 `scripts/` 保留离线测试和构建工具。

## 安装与验证

需要 Python 3.10+；实际运行环境记录在 `reports/environment.json`。两个协议依赖位于同级目录。

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ../whatsapp-signal-protocol -e ../whatsapp-protocol-tree-node
python -m pip install -e '.[test]'
python examples/offline_demo.py
python -m pytest -q
ruff check src tests examples scripts
python -m build
python scripts/verify_package.py
```

`verify_package.py` 重新构建 wheel/sdist，将 wheel 安装到临时目录，并用 sdist 内的全部测试复验；不会误用工作区应用源码。依赖仍使用当前环境中的两个协议库。若需刷新覆盖报告，先分别从两个依赖目录运行 pytest，将 JUnit 保存为本项目 `reports/signal-baseline.xml`、`reports/node-baseline.xml`；本项目运行 `python -m pytest --junitxml=reports/application.xml`，完成安装包复验后执行 `python scripts/refresh_reports.py`。本地分析证据与报告保存在被 Git 忽略的 `reports/`，不包含在安装包内。

最新测试结果见 `reports/application.xml`，阶段与原计划逐项覆盖见 `reports/progress.json`、`reports/test-matrix.json`。安装包及安装后测试记录在 `reports/package-verification.json`。测试夹具的密钥都是合成材料，不进入 wheel。

## 模块

| 模块 | 职责 |
|---|---|
| `database`、`store`、`prekeys` | SQLite WAL/FULL 与统一事务；身份、Curve/KEM 预密钥、active SPK、session、SenderKey；持久 ID 分配与显式轮换 |
| `client`、`outbox`、`receiving`、`packets` | 单聊 v3/v4、群 SKDM/skmsg；原子 outbox/inbox、预密钥消费、事件和去重；协议 retry 接收 |
| `payload` | 文本、引用/提及/转发上下文、deviceSent、SKDM、常用媒体描述符、缩略图和扫描布局字段；未知字段保留 |
| `devices`（兼容入口）、`addressing`、`device_discovery`、`device_directory`、`device_notifications`、`routing` | usync 节点、显式 PN/LID 别名、设备缓存、两种 phash、逐设备 fan-out 与自身关联设备包装 |
| `adv` | 对原始 key-index-list 字节验签、身份与时间绑定、有效设备索引过滤；独立 Java 签名向量 |
| `groups_lifecycle` | 群成员/设备快照、事件幂等、SenderKey 轮换和定向重新分发 |
| `stanza`、`control` | message/participants/enc、可信接收路由、ACK 与批量 delivery/read 回执 |
| `retry`、`transport` | retry receipt 与公开 bundle、受限新 attempt；完整节点字节冻结、重启重传和逐目标回执 |
| `media`、`media_files` | mediaKey/KDF、CBC/MAC、双摘要、文件流、sidecar、认证块缓存与完整文件发布 |
| `media_jobs`、`media_layout`、`media_transfer` | 大文件准备、创建时间、缩略图绑定、扫描布局、HTTP 请求/响应适配、上传结果不确定时的恢复与对账 |

### 模块边界与兼容接口

继续使用浅层 `src/whatsapp_e2ee/` 布局；离线测试统一位于 `tests/`。每个运行时模块通过 `__all__` 声明公开接口，内部依赖使用绝对导入。

- `packets` 定义 `Packet`、`Conflict` 与内容摘要，不依赖客户端或数据库；节点、投递和重试模块直接依赖这些共享类型。
- `Client` 保留原有方法签名，组合 `Outbox` 和 `MessageReceiver`。`outbox` 负责持久消息 ID 与请求指纹绑定；producer 的密钥状态更新和密文入库处于同一事务。`receiving` 负责认证解密、重放约束、inbox 和事件提交。
- `database` 管理 schema、连接和嵌套事务；`store` 提供协议记录存取。数据库版本、表结构、键编码及持久数据格式保持不变。
- `addressing` 提供地址与参与者哈希；`device_discovery` 负责纯查询编解码；`device_directory` 管理别名和查询快照；`device_notifications` 通过注入的目录处理增量事件。后两者共享同一 store 事务。

包根入口及 `client.Packet`、`client.Conflict`、`store.Database`、`devices` 的既有领域接口继续可用，重导出与新模块是同一对象。`Packet`、`Conflict` 和设备数据类保留原有 pickle 模块路径，支持与拆分前代码双向读取这些值对象；SQLite 仍使用原有 JSON/字节格式。新增代码可直接导入职责模块。原有显式网络适配器和调用方式保持不变。

`tests/wire_helpers.py` 为完整节点编码测试提供符合协议地址规则的合成数字账号；普通加密测试和历史算法向量仍保留各自的夹具。模块拆分的契约测试覆盖兼容导入、outbox 失败回滚与重启复用。

接口细节和边界见 [离线契约](docs/offline-contracts.md)。从设备查询到完整节点、回执、群附件和分块下载的可运行示例流程见 `tests/test_end_to_end_pipeline.py`。

## 核心用法

```python
from signal_protocol import SignalProtocolAddress
from whatsapp_e2ee import Client, Database, SQLiteStore, payload
from whatsapp_e2ee.prekeys import PreKeys

store = SQLiteStore(Database("local.db"), "local-device")
store.initialize()  # 仅显式开户；已有身份保持不变
client = Client(store, SignalProtocolAddress("synthetic@s.whatsapp.net", 0))
keys = PreKeys(client)
keys.rotate_signed()  # 明确轮换，不应在每次启动时执行
opk_id = keys.generate(1)[0]
public_bundle = keys.bundle(pre_key_id=opk_id)
```

双方本地会话与媒体使用方式见 `examples/offline_demo.py`。`owner` 表示一个本机设备。远端地址的 account/domain/device、session scope/type 和 SenderKey bucket 分开绑定；PN/LID 映射不自动搬迁身份和会话。

发送业务 protobuf：

```python
packets = client.prepare_direct(
    "message-id", {peer: payload.text("你好")}, bundles={peer: peer_bundle}
)
from whatsapp_e2ee.transport import StanzaDelivery
queue = StanzaDelivery(store)
wire = queue.prepare("message-id", peer.name)
# queue.dispatch("message-id", authorized_transport_send)
```

准备过程中不会调用网络。首次会话需要对应 PreKeyBundle；已有会话不会因普通发送时传入新 bundle 而悄悄重建。相同 ID/输入复用 outbox，冲突报错。网络超时重传已有字节；协议 retry 则创建与原 logical ID 关联的新 attempt 并重新加密，不能回退旧链。

接收使用 `stanza.receive_message(..., authenticated_transport=True, own_device_check=...)`。认证参数由真正的传输边界负责；解析 Node 本身不能证明发送者真实性。自身设备判定需使用可信目录。群 SKDM 和正文共用外部消息 ID，但使用独立内部去重槽，在同一事务完成。合法 retry 再认证后推进状态，正文不可改变，业务事件只落一次。

`DeviceDirectory.apply_query` 默认要求 ADV 验签；身份来源是已信任的主设备记录或显式 `identity_lookup`。没有证明的历史目录只能明确使用 `verification="trusted_snapshot"` 导入；携带证明时仍验签。`DeviceNotifications` 处理远端设备增删和离线失效通知；`GroupNotifications` 处理普通群 add/remove/modify。自身设备生命周期、身份替换和 raw-ID 重置需要上层明确处理，不自动接受。

## 媒体

`MediaJobs.prepare/prepare_file` 在根 key 生成时持久化创建时间，可注入测试时钟或显式创建时间。上传成功只绑定路径，不覆盖 key 创建时间。缩略图复用父根 key/时间、使用独立 HKDF info。

`Uploads` 和下载函数接受显式 transport 回调，不内置 socket、端点发现或鉴权凭据。上传中断保留 `in_flight/unknown`，先对账为 found/absent/unknown；unknown 不自动重新 POST。完整文件/Range 响应严格检查长度、范围及编码。对外输出必须通过完整 MAC、双摘要、padding 和长度校验后原子发布。

`scan_chunk_sizes` 将编码器提供的 scan-length 数组转换为 CBC 块布局；不是搜索 JPEG 标记的猜测分块。媒体元数据执行已核对的扫描数量、长度及 sidecar 条件。编码器、转码和播放器属于调用方。

## 验证与范围

验证包括 SQLite 与内存 Store 契约、历史原引擎记录/密文、v3/v4 与三档 ML-KEM、SenderKey 分发/乱序/轮换、提交失败/进程中断/线程与进程并发、完整消息节点、设备哈希、协议重试、媒体和适配器故障。

历史原引擎夹具重放、独立 Java/Node 向量、Python 自往返、模拟网络和真实服务互通分别记录，不互相替代。特殊 receipt、状态/频道、广播、interop、一次性 SenderKey 及全部产品业务 schema 不会自动套用普通单聊/群聊逻辑。未支持的合法 protobuf 保留原始内容。

离线开发通过不证明服务端接受或任意官方客户端行为；需实时认证状态、设备/群元数据、服务端媒体地址等输入的接口均保持显式。完整证据与仍需外部验证的范围见 `reports/`。
