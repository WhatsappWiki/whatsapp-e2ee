# whatsapp-e2ee

[Telegram: @ttjjda](https://t.me/ttjjda)

[中文](#zh) · [English](#en)

<a id="zh"></a>

## 中文

[English →](#en)

用于 WhatsApp 单聊、群聊和媒体端到端加解密的 Python 工程。提供消息载荷封装、Signal 会话与预密钥、SenderKey 分发、多设备路由、SQLite 持久投递、协议重试，以及媒体加解密和可恢复下载。网络收发通过调用方提供的传输适配器接入。

### 安装与运行

需要 Python 3.10+。将本仓库与以下两个依赖仓库放在同一个父目录中：

- [whatsapp-signal-protocol](https://github.com/WhatsappWiki/whatsapp-signal-protocol)：Signal 会话、预密钥和群 SenderKey。
- [whatsapp-protocol-tree-node](https://github.com/WhatsappWiki/whatsapp-protocol-tree-node)：二进制节点、JID 和节点编解码。

在 `whatsapp-e2ee/` 目录执行：

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ../whatsapp-signal-protocol -e ../whatsapp-protocol-tree-node
python -m pip install -e '.[test]'
python examples/offline_demo.py
python -m pytest -q
ruff check src tests examples
python -m build
```

[离线示例](examples/offline_demo.py) 展示本地端点之间的单聊、群聊和媒体处理。测试套件通过注入的传输回调运行；默认测试边界阻止建立网络连接。构建命令生成 wheel 和源码分发包。

### 模块与目录

运行时代码采用浅层 `src/whatsapp_e2ee/` 布局，离线测试位于 `tests/`，可运行示例位于 `examples/`。各运行时模块通过 `__all__` 声明公开接口，内部使用绝对导入。

| 模块 | 职责 |
| --- | --- |
| `database`、`store`、`prekeys` | SQLite WAL/FULL、嵌套事务；身份、Curve/KEM 预密钥、active SPK、session 和 SenderKey；持久 ID 分配与显式轮换。 |
| `client`、`outbox`、`receiving`、`packets` | 单聊 v3/v4、群 SKDM/skmsg；原子 outbox/inbox、预密钥消费、事件去重和协议重试接收。 |
| `payload` | 文本、引用、提及、转发上下文、deviceSent、SKDM、媒体描述符、缩略图和扫描布局字段；保留未知字段。 |
| `devices`、`addressing`、`device_discovery`、`device_directory`、`device_notifications`、`routing` | 设备查询、PN/LID 别名、设备缓存、参与者哈希、逐设备分发和自身关联设备包装；`devices` 保留兼容导入入口。 |
| `adv` | 原始 key-index-list 字节验签、身份与时间绑定，以及有效设备索引过滤。 |
| `groups_lifecycle`、`group_sessions` | 群成员与设备快照、事件幂等、SenderKey 轮换、定向重新分发及接收检查点合并。 |
| `stanza`、`control` | message/participants/enc 节点、可信接收路由、ACK 和批量 delivery/read 回执。 |
| `retry`、`transport` | retry receipt、公开 bundle 和受限新 attempt；冻结节点字节、重启重传与逐目标回执。 |
| `media`、`media_files` | mediaKey/KDF、CBC/MAC、双摘要、文件流、sidecar、认证块缓存和完整文件发布。 |
| `media_jobs`、`media_layout`、`media_transfer`、`upload_coordination` | 大文件准备、密钥创建时间、缩略图绑定、扫描布局、HTTP 适配，以及上传互斥、恢复与对账。 |

`Client` 组合 `Outbox` 与 `MessageReceiver`：发送方在同一事务中推进密钥状态并保存密文，接收方在认证解密后提交 inbox、去重记录和业务事件。`database` 管理连接、schema 与事务，`store` 提供协议记录存取。

包根入口以及 `client.Packet`、`client.Conflict`、`store.Database` 和 `devices` 的兼容接口继续可用，重导出与职责模块中的对象相同。`Packet`、`Conflict` 和设备数据类保留兼容的 pickle 模块路径；SQLite 使用 JSON 与字节记录。地址 account/domain/device、session scope/type 和 SenderKey bucket 分开绑定，PN/LID 别名绑定不会自动迁移身份或会话。

### 初始化与预密钥

```python
from signal_protocol import SignalProtocolAddress
from whatsapp_e2ee import Client, Database, SQLiteStore
from whatsapp_e2ee.prekeys import PreKeys

store = SQLiteStore(Database("local.db"), "local-device")
store.initialize()  # 显式初始化；已有身份保持不变。
client = Client(store, SignalProtocolAddress("15550001@s.whatsapp.net", 1))
keys = PreKeys(client)
keys.rotate_signed()  # 显式轮换，不应在每次启动时执行。
opk_id = keys.generate(1)[0]
public_bundle = keys.bundle(pre_key_id=opk_id)
```

`owner` 表示一个本机设备。将同一 store 绑定到另一地址会报错。首次建立接收设备会话时提供对应的 `PreKeyBundle`；已有会话不会因普通发送时传入 bundle 而自动重建。

删除或消费预密钥时，在同一事务内记录退役 ID；自动分配会跳过该 `owner` 下同类密钥的现存与退役 ID。last-resort 密钥按原策略保留。备份恢复须保留分配游标与退役记录，已丢失的历史退役 ID 无法从剩余密钥推断。`PreKeys.bundle()` 导出前核对记录 ID，并验证 SPK/KEM 签名与当前本机身份一致；导出不消费密钥，也不自动发布。

新的点对点加解密在提交前核对实际采用的会话身份，包括解密时选中的归档会话。远端身份不再可信或本机身份已改变时，整次消息操作回滚；身份批准与新会话建立由上层显式处理。历史已接受密文仍可返回持久去重结果，不推进会话或新增业务事件。

### 消息准备、投递与接收

以下片段接续上方初始化；`peer` 是目标设备的 `SignalProtocolAddress`，`peer_bundle` 是该设备的公开预密钥包：

```python
from whatsapp_e2ee import payload
from whatsapp_e2ee.transport import StanzaDelivery

packets = client.prepare_direct(
    "message-id", {peer: payload.text("你好")}, bundles={peer: peer_bundle}
)
queue = StanzaDelivery(store)
wire = queue.prepare("message-id", peer.name)
# 调用方提供传输回调后执行：
# queue.dispatch("message-id", transport_send)
```

准备阶段生成并持久化密文，不调用网络。相同消息 ID 与相同输入复用 outbox；同一 ID 对应不同正文或目标时抛出 `Conflict`。传输超时重发已冻结的节点字节；协议 retry 创建与原 logical ID 关联的新 attempt，重新加密并推进链状态。

发送与接收的消息 ID 必须为非空字符串；非法 ID 在推进会话或消费预密钥前拒绝。消息去重按发送设备、群上下文及所选命名空间隔离；业务事件确认后，重复消息或已接受的 retry 不会重新创建待处理事件。

接收入口为 `stanza.receive_message(..., authenticated_transport=True, own_device_check=...)`。传输边界提供认证结果，可信设备目录负责自身设备判定。群 SKDM 与正文共用外部消息 ID，使用独立内部去重槽并在同一事务中处理。经过认证的合法重试可以推进会话状态，但不得改变逻辑正文，业务事件只提交一次。

`own_device_check` 在接收事务内执行，只做本地判定；查询设备目录时须复用客户端的同一个 `Database` 实例。自身设备判定与接收提交使用同一事务，避免并发撤销别名后仍使用旧判定接收自身设备副本。

投递、媒体上传、上传对账、`MediaJobs.prepare_file()`、分块下载和 `RangeDownload.finalize()` 必须在关联数据库的外层事务结束后调用；存在活动事务时抛出 `RuntimeError`，防止网络回调或文件发布依赖尚未提交的检查点。

SQLite 主动回滚整个事务时，所有外层 `atomic()` 块一起失效，并保留原始数据库异常。即使调用方捕获异常，也必须退出最外层事务后才能重试，后续会话与 outbox 写入不能独立提交。只回滚到保存点的普通失败仍允许外层事务继续。

`pending_events()` 读取待处理事件，`acknowledge_event(id)` 标记事件完成。server ACK 与接收设备的 delivery/read 回执分开处理；逐目标回执保持单调状态。

发送回调成功后，stanza 与 outbox 的提交检查点在同一事务内更新；全部数据包已获 ACK 或设备确认时，outbox 也推进到 submitted。整条 stanza 在全部目标已确认后停止重发；部分设备确认仍保留整条冻结节点的重试，群成员回执只更新对应成员。设备专属 ACK 必须匹配目标设备，携带 participant 的群 ACK 必须匹配已冻结的 participant。批量回执每次只更新显式传给 `apply_control` 的消息，其余 ID 由调用方逐条解析应用。

旧记录若已有持久确认但 outbox 仍为 prepared，投递入口会补齐 submitted 状态并停止重发。

普通 ACK 和 delivery/read 解析器在更新状态前拒绝原始负载、非法子节点或嵌套列表项、异常设备地址和空错误值。其他控制形式需要相应业务处理器；发送或读取回执的 ID 均须为非空字符串。

### 设备目录与群生命周期

`DeviceDirectory.apply_query` 默认要求 ADV 验签，身份来自已信任的主设备记录或显式 `identity_lookup`。由外部可信来源提供的无证明快照可显式使用 `verification="trusted_snapshot"`；快照携带证明时仍执行验签。

`DeviceNotifications` 默认沿用目录的身份查询器，也可显式指定独立的 `identity_lookup`；它处理远端设备增删和离线失效通知，`GroupNotifications` 处理普通群的 add/remove/modify。目录更新使用 revision 和有效期约束；过期快照需要显式刷新。群发送冻结成员与设备快照，成员或设备变化可以触发 SenderKey 轮换或定向重新分发。自身设备生命周期、身份替换和 raw-ID 重置由上层显式处理。

群协议重试同时检查调用方提供的当前设备列表、已持久化的群设备快照和本地成员状态。成员被移除或本机退群后，旧设备列表不能使新尝试或已缓存的协议重试通过校验；成员检查与重加密共用事务。历史 outbox 的冻结字节仍可按原批次读取，不会重新分发当前代 SenderKey。群事件 ID 必须为非空字符串，群和成员 JID 必须包含用户部分。

接收方按 key ID 与签名公钥共同区分 SenderKey 代次。同代 SKDM 合并检查点，保留最多 2000 个跳过的消息密钥，不回退接收链；较早的合法检查点可补齐 2000 步以内的历史缺口。更大的前向检查点直接接续，并保留已有缓存，不进行无限派生；仅有较晚检查点不能还原更早的缺失密钥，应保留原分发批次或发起协议重试。接收记录最多保留五个不同代次，重复分发不占用额外代次；轮换发生 key ID 碰撞时通过签名选择对应代次。旧格式的重复记录在接收时合并，SKDM 必须通过绑定群上下文的单聊密文传递。链密钥长度、检查点冲突、签名或后续提交失败时，接收链、单聊会话、inbox 与事件一并回滚。

多设备发送和群初始化的别名、成员校验与持久化共用事务。传给 `prepare_chat` 的目录必须与客户端共用 `Database` 实例和 `owner`。设备 99 默认从对应的 PN/LID 账号读取自身设备快照，发送地址仍保留 `hosted/hosted.lid` 域，且不向本机设备发送副本。

### 媒体处理

`MediaJobs.prepare/prepare_file` 在生成根 key 时持久化创建时间，可注入时钟或显式指定时间。上传成功绑定路径，不覆盖密钥创建时间。缩略图复用父根 key 与创建时间，使用独立 HKDF info。

`Uploads` 与下载函数接收显式 transport 回调；调用方提供端点、认证头和网络实现。上传中断后保留 `in_flight/unknown`，先对账为 found/absent/unknown；unknown 状态不自动重新 POST。

同一数据库、owner 和媒体任务 ID 的发送与对账在工作者之间互斥，竞争操作抛出 `UploadUncertain`；无关任务可独立执行。持久数据库使用旁边的 `.wa-upload-locks/` 协调线程、独立连接与进程，回调期间不持有 SQLite 事务。工作者运行时须保留并共享这些锁文件；进程退出会释放操作锁，原有不确定检查点仍须显式对账。传输与查询回调须同步完成或终止本地操作，不能在返回后继续后台发送；absent 必须来自权威查询，不能由等待时长推断。

互斥层只将获取锁时的竞争失败转换为 `UploadUncertain`；回调异常与取消不被互斥层改写，退出时释放操作锁。

POSIX `fork()` 后，子进程关闭继承的上传锁句柄并重建本地互斥状态，不解锁父进程持有的操作。子进程须重新打开 `Database` 并创建新的上传或对账操作，不能继续继承的活跃回调或数据库连接。父进程操作未结束时，新操作仍被拒绝；结束后按持久化状态恢复，不自动重发。

上传成功记录与待对账状态独立于本地密文缓存保存。即使缓存被清理，已成功上传仍返回原回执，结果不确定时仍要求先对账，不会自动重新 POST。只有新的上传尝试才校验本地密文；对账确认 absent 后若缓存缺失或损坏，须先用相同源文件和已保留的 key 显式重建，再重新上传。显式重建不改变原密钥、创建时间或已有成功记录。

成功记录优先于过期查询结果，已完成任务再次对账会直接复用原回执。`UploadReceipt` 必须包含非空路径、32 字节密文摘要和与密钥创建时间一致的整数毫秒时间戳；空时间戳不会被补成默认值。媒体任务 ID 须为非空字符串。multipart 请求体只消费一次，取完声明长度的字节即视为消费完成；检测到文件增长时不会继续输出超出声明长度的数据。异常上传响应或本地提交失败保留可对账状态，不自动重发。

完整文件和 Range 响应检查长度、范围与编码。对外文件通过完整 MAC、明文与密文双摘要、padding 和长度校验后原子发布。单块认证结果只用于下载恢复，完整文件校验通过后才发布最终输出。

`RangeDownload` 的任务 ID 必须为非空字符串，密文总长度与分块索引必须为整数，不能使用布尔值或浮点值。`missing()` 重新认证缓存块，将损坏块移除并列为缺失，保留其他有效进度；正确认证的新数据可修复损坏的缓存记录。最终组装也检查缓存块及 CBC 前置块，再执行完整文件校验；描述符或主文件校验失败不会把有效块误判为缓存损坏。

完整下载在发起 GET 前校验长度、密钥类型及摘要，并在响应流成功关闭后才解密发布；关闭、校验或文件同步失败时保留原目标文件并清理临时文件。HTTP 长度与范围只接受 ASCII 十进制数字。批量分块下载会保存传入的请求头，使生成器形式的认证头也能用于每个 Range 请求。

`scan_chunk_sizes` 将编码器提供的 scan-length 数组转换为 CBC 块布局；媒体元数据约束扫描数量、长度和 sidecar 条件。编码器、转码器与播放器由调用方提供。

### 测试与接入范围

离线测试覆盖 Store 契约、v3/v4 与三种 ML-KEM 配置、SenderKey 分发/乱序/轮换、提交失败与进程中断、线程与进程并发、完整消息节点、设备哈希、协议重试、媒体认证及适配器故障。兼容性测试覆盖公开导入、值对象序列化、outbox 回滚与重启复用。

[完整处理流程测试](tests/test_end_to_end_pipeline.py) 展示设备查询、节点组装、回执、群附件和分块下载；[模块契约测试](tests/test_module_contracts.py) 展示持久化与兼容接口约束。

[群恢复边界测试](tests/test_group_recovery_boundaries.py) 覆盖成员移除与并发重试、退群、同代乱序分发、旧记录合并、key ID 碰撞、有限密钥缓存和事务失败后的恢复。

调用方接入经过认证的传输、实时账号状态、可信设备与群元数据、服务端媒体地址，以及对应的凭据。Noise 连接层由外部提供。特殊 receipt、状态、频道、广播、interop 和一次性 SenderKey 需要各自的业务处理器；未支持的合法 protobuf 字段保留原始内容。

<a id="en"></a>

## English

[← 中文](#zh)

A Python project for WhatsApp end-to-end encryption of direct messages, group messages, and media. It provides message payloads, Signal sessions and prekeys, SenderKey distribution, multi-device routing, durable SQLite delivery, protocol retries, media encryption and decryption, and resumable downloads. Callers connect network operations through explicit transport adapters.

### Installation and execution

Python 3.10+ is required. Place this repository and the following two dependency repositories under the same parent directory:

- [whatsapp-signal-protocol](https://github.com/WhatsappWiki/whatsapp-signal-protocol): Signal sessions, prekeys, and group SenderKeys.
- [whatsapp-protocol-tree-node](https://github.com/WhatsappWiki/whatsapp-protocol-tree-node): binary nodes, JIDs, and node encoding and decoding.

Run these commands from `whatsapp-e2ee/`:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ../whatsapp-signal-protocol -e ../whatsapp-protocol-tree-node
python -m pip install -e '.[test]'
python examples/offline_demo.py
python -m pytest -q
ruff check src tests examples
python -m build
```

The [offline example](examples/offline_demo.py) demonstrates direct messaging, group messaging, and media processing between local endpoints. The test suite uses injected transport callbacks; its default boundary blocks network connections. The build command generates a wheel and a source distribution.

### Modules and directories

Runtime code uses a shallow `src/whatsapp_e2ee/` layout, offline tests live in `tests/`, and runnable examples live in `examples/`. Each runtime module declares its public interface through `__all__` and uses absolute internal imports.

| Modules | Responsibility |
| --- | --- |
| `database`, `store`, `prekeys` | SQLite WAL/FULL and nested transactions; identities, Curve/KEM prekeys, active SPK, sessions, and SenderKeys; persistent ID allocation and explicit rotation. |
| `client`, `outbox`, `receiving`, `packets` | Direct v3/v4 messages and group SKDM/skmsg; atomic outbox/inbox, prekey consumption, event deduplication, and reception of protocol retries. |
| `payload` | Text, quotes, mentions, forwarding context, deviceSent, SKDM, media descriptors, thumbnails, and scan layout fields; unknown fields are preserved. |
| `devices`, `addressing`, `device_discovery`, `device_directory`, `device_notifications`, `routing` | Device discovery, PN/LID aliases, device caches, participant hashes, per-device distribution, and linked-device wrappers; `devices` retains compatible import paths. |
| `adv` | Signature verification over original key-index-list bytes, identity and time binding, and filtering of valid device indexes. |
| `groups_lifecycle`, `group_sessions` | Group member and device snapshots, event idempotency, SenderKey rotation, targeted redistribution, and receiving-checkpoint merging. |
| `stanza`, `control` | message/participants/enc nodes, trusted receive routing, ACKs, and batched delivery/read receipts. |
| `retry`, `transport` | Retry receipts, public bundles, and bounded new attempts; frozen node bytes, retransmission after restart, and per-target receipts. |
| `media`, `media_files` | mediaKey/KDF, CBC/MAC, dual hashes, file streams, sidecars, authenticated chunk caches, and complete-file publication. |
| `media_jobs`, `media_layout`, `media_transfer`, `upload_coordination` | Large-file preparation, key creation time, thumbnail binding, scan layouts, HTTP adapters, and upload exclusion, recovery, and reconciliation. |

`Client` composes `Outbox` and `MessageReceiver`: senders advance key state and persist ciphertext in the same transaction, while receivers commit the inbox, deduplication records, and business events after authenticated decryption. `database` owns connections, the schema, and transactions; `store` provides protocol record access.

The package root and compatibility interfaces in `client.Packet`, `client.Conflict`, `store.Database`, and `devices` remain available. Re-exports refer to the same objects as the focused modules. `Packet`, `Conflict`, and device data classes retain compatible pickle module paths; SQLite uses JSON and byte records. Address account/domain/device, session scope/type, and SenderKey bucket are bound separately. Binding a PN/LID alias does not automatically migrate identities or sessions.

### Initialization and prekeys

```python
from signal_protocol import SignalProtocolAddress
from whatsapp_e2ee import Client, Database, SQLiteStore
from whatsapp_e2ee.prekeys import PreKeys

store = SQLiteStore(Database("local.db"), "local-device")
store.initialize()  # Explicit initialization; an existing identity is preserved.
client = Client(store, SignalProtocolAddress("15550001@s.whatsapp.net", 1))
keys = PreKeys(client)
keys.rotate_signed()  # Explicit rotation; do not run this on every startup.
opk_id = keys.generate(1)[0]
public_bundle = keys.bundle(pre_key_id=opk_id)
```

`owner` identifies one local device. Binding the same store to another address raises an error. Provide the corresponding `PreKeyBundle` when establishing a recipient-device session for the first time. Passing a bundle during an ordinary send does not automatically rebuild an existing session.

Deleting or consuming a prekey records its retired ID in the same transaction. Automatic allocation skips existing and retired IDs for that key type and `owner`. Last-resort keys retain their existing reuse policy. Backup recovery must preserve allocation cursors and retirement records; lost historical retired IDs cannot be inferred from remaining keys. Before export, `PreKeys.bundle()` checks record IDs and verifies SPK/KEM signatures against the current local identity. Export neither consumes keys nor publishes them automatically.

New pairwise encryption and decryption check the identity of the session actually used before committing, including archived sessions selected during decryption. If the remote identity is no longer trusted or the local identity has changed, the entire message operation rolls back. Identity approval and new-session establishment remain explicit caller responsibilities. Previously accepted ciphertext can still return its durable deduplication result without advancing a session or creating another business event.

### Message preparation, delivery, and reception

The following snippet continues the initialization above. `peer` is the target device's `SignalProtocolAddress`, and `peer_bundle` is its public prekey bundle:

```python
from whatsapp_e2ee import payload
from whatsapp_e2ee.transport import StanzaDelivery

packets = client.prepare_direct(
    "message-id", {peer: payload.text("你好")}, bundles={peer: peer_bundle}
)
queue = StanzaDelivery(store)
wire = queue.prepare("message-id", peer.name)
# Dispatch after providing a transport callback:
# queue.dispatch("message-id", transport_send)
```

Preparation generates and persists ciphertext without network calls. The same message ID and inputs reuse the outbox; different content or targets for the same ID raise `Conflict`. Transport timeouts retransmit frozen node bytes. Protocol retries create a new attempt linked to the original logical ID, encrypt again, and advance chain state.

Message IDs for sending and receiving must be nonempty strings; invalid IDs are rejected before session advancement or prekey consumption. Message deduplication is isolated by sender device, group context, and selected namespace. After a business event is acknowledged, duplicate messages and previously accepted retries do not recreate pending events.

The receive entry point is `stanza.receive_message(..., authenticated_transport=True, own_device_check=...)`. The transport boundary supplies authentication results, and a trusted device directory determines whether a sender is a local linked device. Group SKDM and content share an external message ID, use separate internal deduplication slots, and are processed in the same transaction. Authenticated valid retries may advance session state but cannot change the logical body; business events are committed once.

`own_device_check` runs inside the receive transaction and must perform only local checks. Device-directory queries must reuse the client's same `Database` instance. Own-device classification and receive acceptance share one transaction, preventing concurrent alias revocation from leaving a stale authorization for a linked-device copy.

Call dispatch, media upload, upload reconciliation, `MediaJobs.prepare_file()`, range download, and `RangeDownload.finalize()` after the associated database's outer transaction has ended. An active transaction raises `RuntimeError`, preventing network callbacks or file publication from relying on uncommitted checkpoints.

If SQLite rolls back the entire transaction, all enclosing `atomic()` blocks become unusable and the original database exception is preserved. Even if the caller catches that exception, it must exit the outermost transaction before retrying; later session and outbox writes cannot commit independently. An ordinary failure rolled back to a savepoint still allows the outer transaction to continue.

`pending_events()` reads pending events, and `acknowledge_event(id)` marks an event complete. Server ACKs are handled separately from recipient-device delivery/read receipts; per-target receipt state is monotonic.

After a successful send callback, stanza and outbox submission checkpoints update in one transaction. The outbox also advances to submitted when all packets have an ACK or device confirmation. Whole-stanza retransmission stops once every target is confirmed; partial confirmation retains retries of the entire frozen node, and group-member receipts update only that member. Device-specific ACKs must match the destination device, and group ACKs carrying a participant must match the frozen participant. Each batched-receipt application updates only the message explicitly passed to `apply_control`; the caller resolves and applies the other IDs individually.

For legacy records with durable confirmation but an outbox still marked prepared, dispatch repairs the submitted checkpoint and suppresses retransmission.

Ordinary ACK and delivery/read parsers reject raw payloads, invalid children or nested list items, invalid device addresses, and empty error values before updating state. Other control forms need their corresponding business handlers. IDs used to send or acknowledge receipts must be nonempty strings.

### Device directory and group lifecycle

`DeviceDirectory.apply_query` requires ADV verification by default. Identity comes from a trusted primary-device record or an explicit `identity_lookup`. A snapshot without proof supplied by an external trusted source can explicitly use `verification="trusted_snapshot"`; any proof present in a snapshot is still verified.

`DeviceNotifications` uses the directory's identity lookup by default and accepts an explicit separate `identity_lookup`. It handles remote device additions, removals, and offline invalidation notifications. `GroupNotifications` handles ordinary group add/remove/modify events. Directory updates are constrained by revisions and expiry times; expired snapshots require an explicit refresh. Group sends freeze member and device snapshots. Membership or device changes can trigger SenderKey rotation or targeted redistribution. The caller explicitly handles local-device lifecycle, identity replacement, and raw-ID resets.

Group protocol retries check the caller's current device list, the persisted group-device snapshot, and local membership state together. After a recipient is removed or the local account leaves, a stale device list cannot authorize a new attempt or a cached protocol retry. Membership checks and re-encryption share a transaction. Frozen bytes from historical outbox batches remain readable without redistributing the current SenderKey generation. Group event IDs must be nonempty strings, and group and member JIDs must include a user part.

Receivers distinguish SenderKey generations by both key ID and signing public key. Same-generation SKDMs merge checkpoints, retain at most 2000 skipped message keys, and never rewind the receiving chain. An earlier valid checkpoint can fill historical gaps within 2000 steps. Larger forward checkpoints resume directly while preserving existing cached keys, without unbounded derivation. A later checkpoint alone cannot recover earlier missing keys; retain the original distribution batch or request a protocol retry. Receiving records retain at most five distinct generations, and repeat distributions do not consume additional generation slots. Signatures select the matching generation when rotated key IDs collide. Legacy duplicate records merge during reception. SKDMs must arrive in pairwise ciphertext bound to the group context. Invalid chain-key lengths, conflicting checkpoints, signature failures, or subsequent commit failures roll back the receiving chain, pairwise session, inbox, and events together.

Alias and membership checks for multi-device sends and group initialization share the persistence transaction. A directory passed to `prepare_chat` must share the client's `Database` instance and `owner`. Device 99 defaults to its corresponding PN/LID account for the own-device snapshot, retains its `hosted/hosted.lid` sending address, and excludes itself from linked-device copies.

### Media processing

`MediaJobs.prepare/prepare_file` persists creation time when generating the root key and accepts an injected clock or an explicit time. A successful upload binds a path without replacing key creation time. Thumbnails reuse the parent's root key and creation time with separate HKDF info.

`Uploads` and download functions accept explicit transport callbacks. Callers provide endpoints, authentication headers, and network implementations. Interrupted uploads retain `in_flight/unknown` state and are first reconciled as found/absent/unknown; an unknown result does not automatically trigger another POST.

Sending and reconciliation for the same database, owner, and media job ID are mutually exclusive across workers; competing operations raise `UploadUncertain`, while unrelated jobs can proceed independently. Persistent databases use the adjacent `.wa-upload-locks/` directory to coordinate threads, separate connections, and processes without holding a SQLite transaction during callbacks. Keep and share these lock files while workers run. Process exit releases operation ownership, but an uncertain checkpoint still requires explicit reconciliation. Transport and lookup callbacks must synchronously finish or terminate their local operation and must not continue sending in the background after returning. An absent result must come from an authoritative lookup, never elapsed time alone.

The coordination layer converts only lock-acquisition contention into `UploadUncertain`. It preserves callback exceptions and cancellation and releases operation ownership on exit.

After POSIX `fork()`, the child closes inherited upload-lock handles and rebuilds local ownership state without unlocking the parent's operations. The child must reopen `Database` and start new upload or reconciliation operations rather than continue inherited active callbacks or database connections. New operations remain excluded while the parent owns the job; afterward they recover from durable state without automatic retransmission.

Successful upload records and pending reconciliation state persist independently of the local encrypted cache. If the cache is removed, a completed upload still returns its recorded receipt, and an uncertain upload still requires reconciliation without an automatic new POST. Only a new upload attempt validates local ciphertext. After an absent result, a missing or damaged cache must be explicitly rebuilt from the same source file and retained key before another upload. Explicit rebuilding preserves the original key, creation time, and any successful upload record.

Durable completion takes precedence over stale lookup results, and reconciliation of an already completed job reuses its original receipt. `UploadReceipt` must contain a nonempty path, a 32-byte encrypted hash, and an integer millisecond timestamp matching key creation time; a missing timestamp is not replaced with a default. Media job IDs must be nonempty strings. A multipart body is consumed once and is complete when its declared bytes have been obtained. Detected file growth cannot emit bytes beyond the declared length. Invalid upload responses and local commit failures retain a recoverable state without automatic retransmission.

Complete-file and Range responses are checked for length, range, and encoding. Output files are published atomically after full MAC, plaintext and ciphertext hashes, padding, and length checks pass. Individual authenticated chunks support download recovery; final output is published only after complete-file verification.

`RangeDownload` job IDs must be nonempty strings, and encrypted totals and chunk indexes must be integers rather than booleans or floats. `missing()` reauthenticates cached chunks, removes damaged entries and lists them as missing while retaining valid progress. Fresh authenticated bytes can repair damaged cache records. Final assembly also checks cached chunks and their preceding CBC blocks before complete-file verification; a descriptor or main-file verification failure does not misclassify valid chunks as cache corruption.

Complete downloads validate lengths, key types, and hashes before issuing GET and decrypt for publication only after the response stream closes successfully. Close, verification, or file-sync failures preserve the original destination and remove temporary files. HTTP lengths and ranges accept only ASCII decimal digits. Batched range downloads retain supplied headers so authentication headers passed as a generator are used for every Range request.

`scan_chunk_sizes` converts an encoder-supplied scan-length array into a CBC block layout. Media metadata constrains scan counts, lengths, and sidecar conditions. Callers provide encoders, transcoders, and players.

### Tests and integration scope

Offline tests cover Store contracts, v3/v4 and three ML-KEM configurations, SenderKey distribution/reordering/rotation, commit failures and process interruption, thread and process concurrency, complete message nodes, device hashes, protocol retries, media authentication, and adapter failures. Compatibility tests cover public imports, value serialization, outbox rollback, and reuse after restart.

The [complete pipeline tests](tests/test_end_to_end_pipeline.py) demonstrate device discovery, node assembly, receipts, group attachments, and chunked downloads. The [module contract tests](tests/test_module_contracts.py) demonstrate persistence and compatibility interface constraints.

The [group recovery boundary tests](tests/test_group_recovery_boundaries.py) cover membership removal with concurrent retries, local departure, reordered same-generation distributions, legacy-record merging, key ID collisions, bounded key caches, and recovery after transaction failures.

Callers supply authenticated transport, live account state, trusted device and group metadata, server media addresses, and the corresponding credentials. The Noise connection layer is supplied externally. Special receipts, status, channels, broadcasts, interop, and one-time SenderKey require their own business handlers; unsupported valid protobuf fields retain their original content.
