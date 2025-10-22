# 喵盾 FRP 隧检器 | CatTunGuard

一款高效的FRP隧道违规使用检测工具，针对**星穿月联内网映射项目组**开发，适配星穿月联FRP服务的API接口，可自动识别在线隧道中的违规内容与不合规配置，生成详细检测报告，帮助管理员快速排查风险。


## 功能特点

- **自动化隧道采集**：通过星穿月联FRP服务API批量获取所有在线隧道数据，支持分页自动处理
- **智能检测范围**：自动筛选需重点关注的隧道（HTTP/HTTPS类型、绑定Web端口的TCP隧道、带域名的隧道）
- **内容违规识别**：检测网页内容中是否包含色情、赌博、枪支等违规关键词
- **域名合规分析**：识别绑定域名是否为IP地址，标记需确认备案状态的域名
- **多线程高效处理**：采用线程池并发检测，提升大规模隧道的处理效率
- **详细报告导出**：自动生成Excel格式报告，包含隧道信息、违规证据及检测时间
- **错误容错机制**：内置错误计数与上限控制，避免单次异常中断整体检测流程


## 适用范围

本工具针对**星穿月联内网映射平台**设计，适配其FRP服务管理员API接口，可直接用于该平台的隧道合规性检测。


## 快速使用指南

### 环境要求
- Python 3.6+
- 依赖库：`requests`、`openpyxl`、`maskpass`


### 安装步骤

1. 克隆仓库或下载代码：
   ```bash
   git clone https://github.com/catcumin/cattunguard.git
   cd cattunguard
   ```

2. 安装依赖：
   ```bash
   pip install requests openpyxl maskpass
   ```


### 运行程序

1. **配置API与Token**（关键步骤）：
   - 工具默认适配星穿月联FRP服务的API，若平台API地址有变更，需修改代码中`BASE_API`参数：
     ```python
     # 星穿月联FRP服务的在线隧道API地址（可根据实际平台修改）
     BASE_API = "https://console.frp.api.xhuzim.top/api/v1/admin/proxies?status=online"
     ```
   - 需从星穿月联平台获取管理员认证Token（用于API访问权限验证），运行时会提示输入


2. 执行主程序：
   ```bash
   python CatTunGuard_v1.0.6.py
   ```
   或
      ```bash
   运行 CatTunGuard.exe
   ```

3. 输入管理员认证Token：
   - 程序会验证Token有效性，最多允许5次输入尝试
   - Token验证通过后自动开始检测流程

4. 查看结果：
   - 检测完成后，结果会导出为Excel文件（文件名格式：`frp_violation_check_时间戳.xlsx`）
   - 报告包含隧道ID、用户名、违规状态、证据等详细信息


## API接口说明

### 接口地址
默认使用星穿月联FRP服务的在线隧道列表API：
```
https://console.frp.api.xhuzim.top/api/v1/admin/proxies?status=online
```
- 需通过`page`和`page_size`参数分页获取数据（工具已内置分页处理逻辑）
- 需在请求头中携带`Authorization: [Token]`进行身份验证


### 返回数据格式
API返回JSON格式数据，结构如下（星穿月联平台标准响应）：
```json
{
    "code": 200,  // 200表示请求成功
    "msg": "获取成功",  // 状态描述
    "pagination": {  // 分页信息
        "page": 1,  // 当前页码
        "page_size": 10,  // 每页条数
        "pages": 13,  // 总页数
        "total": 130  // 总隧道数
    },
    "proxies": [  // 隧道列表数据
        {
            "domain": "pan.twskyhope.top",  // 绑定的域名
            "id": 2389,  // 隧道ID
            "lastupdate": "2025-10-22 15:20:04",  // 最后更新时间
            "link": "https://pan.twskyhope.top",  // 外网访问地址
            "local_ip": "192.168.1.222",  // 内网IP
            "local_port": 80,  // 内网端口
            "node_name": "日本东京#1【普通节点】",  // 节点名称
            "proxy_type": "https",  // 代理类型（http/https/tcp等）
            "status": "online",  // 状态（online表示在线）
            "username": "kkk025"  // 隧道所属用户
            // 其他字段：略
        },
        // 更多隧道数据...
    ]
}
```
- 工具依赖`proxies`数组中的隧道数据进行检测，若平台API返回格式不同，需调整`fetch_all_tunnels`方法中的解析逻辑


## 配置说明

程序核心配置项位于`FRPViolationChecker`类的`__init__`方法中，可根据需求调整：

```python
self.config = {
    "timeout": 8,  # 网页访问超时时间（秒）
    "max_workers": 5,  # 并发线程数
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",  # 爬虫模拟浏览器UA
    "violation_keywords": ["色情", "赌博", "枪支", "违法", "私服", "外挂"],  # 违规关键词库
    "web_local_ports": {"80", "8080", "8000", "443", "8888", "9000"},  # 需重点检测的Web端口
    "html_indicators": {"<html", "<head", "<body", "<title", "<meta"}  # 网页特征标识（用于判断是否为网页内容）
}
```

- 扩展检测范围：可添加更多`violation_keywords`（如新增违规词汇）或`web_local_ports`（如新增常用Web端口）
- 性能调整：`max_workers`值越大检测速度越快，但可能增加服务器负载，建议根据隧道数量调整


## 检测逻辑说明

1. **需检测的隧道类型**：
   - HTTP/HTTPS类型的隧道（直接提供网页服务）
   - 绑定80、443、8080等常见Web端口的TCP隧道（可能用于网页服务）
   - 已绑定域名的隧道（需确认域名备案状态）

2. **违规判定标准**：
   - 网页内容中包含`violation_keywords`中的违规关键词
   - HTTP/HTTPS隧道绑定非IP形式的域名（需人工确认备案状态）


## 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源协议，允许自由使用、修改和分发，详情参见许可证文件。


## 开发者信息

- 开发者：catcumin (猫宁孜)
- 版本：v1.0.6
- 更新日期：2025-10-22
- 适配平台：星穿月联内网映射平台
- 反馈邮箱：969008120@qq.com
- GitHub：https://github.com/catcumin
