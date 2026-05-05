# Loon 规则聚合器：语义去重 + 保留原格式版

这个版本适合你的需求：

> 规则源本身已经符合 Loon / Surge 规则格式，所以输出不转换格式；内部解析成规则对象做更聪明的去重。

## 已内置规则源

```text
AWAvenue-Ads-Rule：priority 5
Aethersailor-adblockloonlite：priority 4
anti-AD-surge2：priority 3
Cats-Team-AdRules：priority 2
```

配置位置：

```text
config/sources.json
```

每个规则源都有单独开关：

```json
{
  "name": "anti-AD-surge2",
  "enabled": true,
  "priority": 3,
  "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge2.txt"
}
```

关闭某个源：

```json
"enabled": false
```

## 去重逻辑

### 1. 结构去重

内部把规则解析成对象：

```text
kind + target + policy + options
```

例如下面两条会认为是同一条：

```text
DOMAIN-SUFFIX, example.com, REJECT
DOMAIN-SUFFIX,example.com,REJECT
```

重复时保留 `priority` 更高来源的原始写法。

### 2. 包含去重

默认开启激进包含去重：

```text
DOMAIN-SUFFIX,example.com,REJECT
```

会覆盖并删除：

```text
DOMAIN,ads.example.com,REJECT
DOMAIN-SUFFIX,track.example.com,REJECT
```

同时：

```text
IP-CIDR,1.2.0.0/16,REJECT
```

会覆盖并删除：

```text
IP-CIDR,1.2.3.0/24,REJECT
```

默认不对下面两类做包含判断：

```text
DOMAIN-KEYWORD
URL-REGEX
```

因为它们容易误判。

## 开关配置

在 `config/sources.json` 里可以关掉包含去重：

```json
"containment": {
  "enabled": false
}
```

也可以只关某一项：

```json
"containment": {
  "enabled": true,
  "domain_suffix_contains_domain": true,
  "domain_suffix_contains_sub_suffix": true,
  "ip_cidr_contains": false,
  "domain_keyword_contains": false,
  "url_regex_contains": false
}
```

## 输出文件

```text
dist/merged-adblock.plugin
```

## 本地运行

```bash
pip install -r requirements.txt
python src/main.py
```

## GitHub Actions

上传 GitHub 后，进入：

```text
Actions → Update Loon AdBlock Plugin → Run workflow
```

生成后订阅 raw 地址：

```text
https://raw.githubusercontent.com/你的用户名/你的仓库名/main/dist/merged-adblock.plugin
```
