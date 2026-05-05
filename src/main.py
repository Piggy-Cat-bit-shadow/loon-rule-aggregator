import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "sources.json"


@dataclass(frozen=True)
class Source:
    name: str
    priority: int
    url: str


@dataclass
class Rule:
    kind: str
    target: str
    policy: str
    options: Tuple[str, ...]
    origin: str
    source: str
    priority: int
    order: int

    @property
    def structural_key(self) -> Tuple[str, str, str, Tuple[str, ...]]:
        return (
            self.kind.upper(),
            normalize_target(self.target),
            self.policy.upper(),
            tuple(x.lower() for x in self.options),
        )


class SemanticAggregator:
    """
    工作方式：
    1. 读取源规则；
    2. 跳过注释、空行、metadata、section header；
    3. 解析为 Rule 对象；
    4. 先做结构去重：kind + target + policy + options；
    5. 可选做包含去重：DOMAIN-SUFFIX 覆盖 DOMAIN / 子 DOMAIN-SUFFIX，IP-CIDR 大网段覆盖小网段；
    6. 输出仍保留被保留下来的原始规则行，不转换格式。
    """

    def __init__(self, dedupe_cfg: dict):
        self.dedupe_cfg = dedupe_cfg or {}
        self.rules_by_key: Dict[Tuple[str, str, str, Tuple[str, ...]], Rule] = {}
        self.unknown_by_key: Dict[str, Rule] = {}
        self.stats: List[str] = []
        self.order_counter = 0
        self.dropped_containment = 0

    def parse_text(self, text: str, source: Source):
        before = self.total_rules()

        for raw in text.splitlines():
            line = clean_line(raw)
            if not line or should_skip_line(line):
                continue

            self.order_counter += 1
            rule = parse_rule_line(
                line=line,
                source_name=source.name,
                priority=source.priority,
                order=self.order_counter,
            )

            if rule is None:
                # 不认识的行也保留，但只做文本级去重
                key = text_key(line)
                old = self.unknown_by_key.get(key)
                if old is None or better(rule_candidate_priority=source.priority, rule_candidate_order=self.order_counter,
                                         old_priority=old.priority, old_order=old.order):
                    self.unknown_by_key[key] = Rule(
                        kind="UNKNOWN",
                        target=key,
                        policy="",
                        options=(),
                        origin=line,
                        source=source.name,
                        priority=source.priority,
                        order=self.order_counter,
                    )
                continue

            key = rule.structural_key
            old = self.rules_by_key.get(key)
            if old is None or better(rule.priority, rule.order, old.priority, old.order):
                self.rules_by_key[key] = rule

        after = self.total_rules()
        self.stats.append(f"{source.name}: +{after - before}")

    def total_rules(self) -> int:
        return len(self.rules_by_key) + len(self.unknown_by_key)

    def all_rules(self) -> List[Rule]:
        rules = list(self.rules_by_key.values()) + list(self.unknown_by_key.values())
        if self.dedupe_cfg.get("containment", {}).get("enabled", False):
            rules = self.apply_containment_dedupe(rules)
        return rules

    def apply_containment_dedupe(self, rules: List[Rule]) -> List[Rule]:
        cfg = self.dedupe_cfg.get("containment", {})
        remove_ids = set()

        domain_suffix_rules = [
            r for r in rules
            if r.kind.upper() == "DOMAIN-SUFFIX" and r.policy.upper().startswith("REJECT")
        ]
        domain_rules = [
            r for r in rules
            if r.kind.upper() == "DOMAIN" and r.policy.upper().startswith("REJECT")
        ]

        suffixes = []
        for r in domain_suffix_rules:
            host = normalize_domain(r.target)
            if host:
                suffixes.append((host, r))

        # DOMAIN-SUFFIX 覆盖 DOMAIN
        if cfg.get("domain_suffix_contains_domain", True):
            for r in domain_rules:
                host = normalize_domain(r.target)
                if not host:
                    continue
                covering = find_covering_suffix(host, suffixes)
                if covering is not None:
                    remove_ids.add(id(r))

        # DOMAIN-SUFFIX 覆盖更深的 DOMAIN-SUFFIX
        if cfg.get("domain_suffix_contains_sub_suffix", True):
            sorted_suffixes = sorted(suffixes, key=lambda x: suffix_depth(x[0]))
            for host, r in sorted_suffixes:
                for parent, parent_rule in sorted_suffixes:
                    if id(parent_rule) == id(r):
                        continue
                    if suffix_depth(parent) >= suffix_depth(host):
                        continue
                    if domain_is_under(host, parent):
                        remove_ids.add(id(r))
                        break

        # IP-CIDR 大网段覆盖小网段
        if cfg.get("ip_cidr_contains", True):
            cidr_rules = [
                r for r in rules
                if r.kind.upper() in {"IP-CIDR", "IP-CIDR6"} and r.policy.upper().startswith("REJECT")
            ]
            networks: List[Tuple[ipaddress._BaseNetwork, Rule]] = []
            for r in cidr_rules:
                try:
                    networks.append((ipaddress.ip_network(r.target, strict=False), r))
                except Exception:
                    pass

            networks.sort(key=lambda x: (x[0].version, x[0].prefixlen))
            for net, r in networks:
                for parent_net, parent_rule in networks:
                    if id(parent_rule) == id(r):
                        continue
                    if parent_net.version != net.version:
                        continue
                    if parent_net.prefixlen >= net.prefixlen:
                        continue
                    if net.subnet_of(parent_net):
                        remove_ids.add(id(r))
                        break

        self.dropped_containment = len(remove_ids)
        return [r for r in rules if id(r) not in remove_ids]

    def render(self, plugin_cfg: dict) -> str:
        rules = self.all_rules()

        out: List[str] = []
        out.append(f"#!name={plugin_cfg.get('name', 'Merged Loon AdBlock')}")
        out.append(f"#!desc={plugin_cfg.get('desc', 'Merged Loon adblock rules')}")
        out.append(f"#!author={plugin_cfg.get('author', 'unknown')}")
        if plugin_cfg.get("homepage"):
            out.append(f"#!homepage={plugin_cfg['homepage']}")
        if plugin_cfg.get("icon"):
            out.append(f"#!icon={plugin_cfg['icon']}")
        out.append("")
        out.append("# Generated by loon-rule-aggregator")
        out.append("# Mode: semantic dedupe, preserve original rule format")
        out.append("# Source stats:")
        for stat in self.stats:
            out.append(f"# - {stat}")
        out.append(f"# Structural unique rules before containment: {self.total_rules()}")
        out.append(f"# Dropped by containment dedupe: {self.dropped_containment}")
        out.append(f"# Final rules: {len(rules)}")
        out.append("")

        out.append("[Rule]")
        # 按原始出现顺序输出，更接近源规则顺序；如果你想字母排序，可改成 key=lambda r: r.origin.lower()
        for r in sorted(rules, key=lambda x: x.order):
            out.append(r.origin)
        out.append("")

        return "\n".join(out).rstrip() + "\n"


def better(rule_candidate_priority: int, rule_candidate_order: int, old_priority: int, old_order: int) -> bool:
    # priority 更高者优先；priority 相同则先出现者优先
    if rule_candidate_priority != old_priority:
        return rule_candidate_priority > old_priority
    return rule_candidate_order < old_order


def clean_line(raw: str) -> str:
    return raw.strip()


def should_skip_line(line: str) -> bool:
    if not line:
        return True
    if line.startswith("#") or line.startswith("//") or line.startswith(";"):
        return True
    if line.startswith("#!"):
        return True
    if line.startswith("[") and line.endswith("]"):
        return True
    return False


def split_rule(line: str) -> List[str]:
    # Loon/Surge/Clash 规则核心都是逗号分隔；这里不处理 URL-REGEX 内部逗号的极端情况
    return [p.strip() for p in line.split(",")]


def parse_rule_line(line: str, source_name: str, priority: int, order: int) -> Optional[Rule]:
    parts = split_rule(line)
    if len(parts) < 2:
        return None

    kind = parts[0].upper()
    supported = {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-SET",
        "RULE-SET",
        "IP-CIDR",
        "IP-CIDR6",
        "URL-REGEX",
        "USER-AGENT",
        "PROCESS-NAME",
        "DST-PORT",
        "GEOIP",
        "FINAL",
    }

    if kind not in supported:
        return None

    # FINAL 这种可能只有 FINAL,PROXY；本项目广告过滤源通常不会有
    if kind == "FINAL":
        target = "FINAL"
        policy = parts[1] if len(parts) >= 2 else ""
        options = tuple(parts[2:])
    else:
        target = parts[1]
        policy = parts[2] if len(parts) >= 3 else ""
        options = tuple(parts[3:])

    return Rule(
        kind=kind,
        target=target,
        policy=policy,
        options=options,
        origin=line,
        source=source_name,
        priority=priority,
        order=order,
    )


def text_key(line: str) -> str:
    normalized = line.strip()
    normalized = re.sub(r"\s*,\s*", ",", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.lower()


def normalize_target(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return target
    return target.lower().rstrip(".")


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    d = d.lstrip("*.").lstrip(".")
    if not d or "/" in d or ":" in d:
        return ""
    return d


def suffix_depth(domain: str) -> int:
    return len([p for p in domain.split(".") if p])


def domain_is_under(child: str, parent: str) -> bool:
    child = normalize_domain(child)
    parent = normalize_domain(parent)
    if not child or not parent:
        return False
    return child == parent or child.endswith("." + parent)


def find_covering_suffix(host: str, suffixes: List[Tuple[str, Rule]]) -> Optional[Rule]:
    host = normalize_domain(host)
    if not host:
        return None
    for suffix, rule in suffixes:
        if domain_is_under(host, suffix):
            return rule
    return None


def fetch_url(url: str) -> str:
    headers = {"User-Agent": "loon-rule-aggregator/1.0"}
    resp = requests.get(url, headers=headers, timeout=45)
    resp.raise_for_status()
    resp.encoding = resp.encoding or "utf-8"
    return resp.text


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def main():
    cfg = load_config()
    plugin_cfg = cfg.get("plugin", {})
    dedupe_cfg = cfg.get("dedupe", {})

    aggregator = SemanticAggregator(dedupe_cfg=dedupe_cfg)

    enabled_sources: List[Source] = []
    for item in cfg.get("sources", []):
        if not item.get("enabled", True):
            continue
        url = item.get("url", "").strip()
        if not url:
            continue
        enabled_sources.append(Source(
            name=item.get("name") or urlparse(url).netloc or "source",
            priority=int(item.get("priority", 0)),
            url=url,
        ))

    if not enabled_sources:
        print("No enabled sources. Please edit config/sources.json")
        return 1

    for source in enabled_sources:
        try:
            print(f"Fetching {source.name}: {source.url}")
            text = fetch_url(source.url)
            aggregator.parse_text(text, source)
        except Exception as e:
            print(f"[WARN] Failed to fetch/parse {source.name}: {e}", file=sys.stderr)

    output_rel = plugin_cfg.get("output", "dist/merged-adblock.plugin")
    output_path = ROOT / output_rel
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(aggregator.render(plugin_cfg), encoding="utf-8")

    final_rules = len(aggregator.all_rules())
    print(f"Done: {output_path}")
    print(f"Structural unique rules before containment: {aggregator.total_rules()}")
    print(f"Dropped by containment dedupe: {aggregator.dropped_containment}")
    print(f"Final rules: {final_rules}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
