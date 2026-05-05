import ipaddress
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
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


@dataclass
class SourceStats:
    name: str
    url: str
    raw_lines: int = 0
    skipped_lines: int = 0
    recognized_rules: int = 0
    unknown_kept: int = 0
    duplicates: int = 0
    added_unique: int = 0
    replaced_by_priority: int = 0
    kind_counter: Counter = field(default_factory=Counter)


class SemanticAggregator:
    def __init__(self, dedupe_cfg: dict):
        self.dedupe_cfg = dedupe_cfg or {}
        self.rules_by_key: Dict[Tuple[str, str, str, Tuple[str, ...]], Rule] = {}
        self.unknown_by_key: Dict[str, Rule] = {}

        self.source_stats: List[SourceStats] = []
        self.order_counter = 0

        self.dropped_containment = 0
        self.dropped_domain_by_suffix = 0
        self.dropped_suffix_by_suffix = 0
        self.dropped_cidr_by_cidr = 0

    def parse_text(self, text: str, source: Source):
        stats = SourceStats(name=source.name, url=source.url)
        before = self.total_rules()

        for raw in text.splitlines():
            stats.raw_lines += 1
            line = clean_line(raw)

            if should_skip_line(line):
                stats.skipped_lines += 1
                continue

            self.order_counter += 1
            rule = parse_rule_line(
                line=line,
                source_name=source.name,
                priority=source.priority,
                order=self.order_counter,
            )

            if rule is None:
                key = text_key(line)
                old = self.unknown_by_key.get(key)

                if old is None:
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
                    stats.unknown_kept += 1
                else:
                    stats.duplicates += 1
                    if better(source.priority, self.order_counter, old.priority, old.order):
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
                        stats.replaced_by_priority += 1
                continue

            stats.recognized_rules += 1
            stats.kind_counter[rule.kind.upper()] += 1

            key = rule.structural_key
            old = self.rules_by_key.get(key)

            if old is None:
                self.rules_by_key[key] = rule
            else:
                stats.duplicates += 1
                if better(rule.priority, rule.order, old.priority, old.order):
                    self.rules_by_key[key] = rule
                    stats.replaced_by_priority += 1

        after = self.total_rules()
        stats.added_unique = after - before
        self.source_stats.append(stats)
        print_source_stats(stats)

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

        if cfg.get("domain_suffix_contains_domain", True):
            for r in domain_rules:
                host = normalize_domain(r.target)
                if not host:
                    continue

                if find_covering_suffix(host, suffixes) is not None:
                    if id(r) not in remove_ids:
                        self.dropped_domain_by_suffix += 1
                    remove_ids.add(id(r))

        if cfg.get("domain_suffix_contains_sub_suffix", True):
            sorted_suffixes = sorted(suffixes, key=lambda x: suffix_depth(x[0]))

            for host, r in sorted_suffixes:
                for parent, parent_rule in sorted_suffixes:
                    if id(parent_rule) == id(r):
                        continue
                    if suffix_depth(parent) >= suffix_depth(host):
                        continue
                    if domain_is_under(host, parent):
                        if id(r) not in remove_ids:
                            self.dropped_suffix_by_suffix += 1
                        remove_ids.add(id(r))
                        break

        if cfg.get("ip_cidr_contains", True):
            cidr_rules = [
                r for r in rules
                if r.kind.upper() in {"IP-CIDR", "IP-CIDR6"}
                and r.policy.upper().startswith("REJECT")
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
                        if id(r) not in remove_ids:
                            self.dropped_cidr_by_cidr += 1
                        remove_ids.add(id(r))
                        break

        self.dropped_containment = len(remove_ids)
        return [r for r in rules if id(r) not in remove_ids]

    def merged_kind_counter(self, rules: List[Rule]) -> Counter:
        counter = Counter()
        for r in rules:
            counter[r.kind.upper()] += 1
        return counter

    def total_raw_lines(self) -> int:
        return sum(s.raw_lines for s in self.source_stats)

    def total_skipped_lines(self) -> int:
        return sum(s.skipped_lines for s in self.source_stats)

    def total_recognized_rules(self) -> int:
        return sum(s.recognized_rules for s in self.source_stats)

    def total_unknown_kept(self) -> int:
        return sum(s.unknown_kept for s in self.source_stats)

    def total_duplicates(self) -> int:
        return sum(s.duplicates for s in self.source_stats)

    def total_replaced_by_priority(self) -> int:
        return sum(s.replaced_by_priority for s in self.source_stats)

    def render(self, plugin_cfg: dict) -> str:
        rules = self.all_rules()
        kind_counter = self.merged_kind_counter(rules)

        out: List[str] = []
        out.append(f"#!name={plugin_cfg.get('name', 'Merged Loon AdBlock')}")
        out.append(f"#!desc={plugin_cfg.get('desc', 'Merged Loon adblock rules')}")
        out.append(f"#!author={plugin_cfg.get('author', 'unknown')}")

        if plugin_cfg.get("homepage"):
            out.append(f"#!homepage={plugin_cfg['homepage']}")

        if plugin_cfg.get("icon"):
            out.append(f"#!icon={plugin_cfg['icon']}")

        out.append("")
        out.append("# 由 loon-rule-aggregator 自动生成")
        out.append("# 模式：语义去重，保留原始规则格式")
        out.append("#")
        out.append(f"# 原始总行数：{fmt(self.total_raw_lines())}")
        out.append(f"# 跳过行数：{fmt(self.total_skipped_lines())}")
        out.append(f"# 有效规则数：{fmt(self.total_recognized_rules())}")
        out.append(f"# 未识别但保留：{fmt(self.total_unknown_kept())}")
        out.append(f"# 结构重复数：{fmt(self.total_duplicates())}")
        out.append(f"# 优先级替换数：{fmt(self.total_replaced_by_priority())}")
        out.append(f"# 包含去重前：{fmt(self.total_rules())}")
        out.append(f"# 包含去重删除：{fmt(self.dropped_containment)}")
        out.append(f"# 最终规则数：{fmt(len(rules))}")
        out.append("#")
        out.append("# 最终规则类型：")

        for kind, count in kind_counter.most_common():
            out.append(f"# - {kind}: {fmt(count)}")

        out.append("")
        out.append("[Rule]")

        for r in sorted(rules, key=lambda x: x.order):
            out.append(r.origin)

        out.append("")
        return "\n".join(out).rstrip() + "\n"


def better(rule_candidate_priority: int, rule_candidate_order: int, old_priority: int, old_order: int) -> bool:
    if rule_candidate_priority != old_priority:
        return rule_candidate_priority > old_priority
    return rule_candidate_order < old_order


def clean_line(raw: str) -> str:
    return raw.strip()


def should_skip_line(line: str) -> bool:
    if not line:
        return True

    if line.startswith("#") or line.startswith("//") or line.startswith(";") or line.startswith("#!"):
        return True

    if line.startswith("[") and line.endswith("]"):
        return True

    return False


def split_rule(line: str) -> List[str]:
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


def fmt(num: int) -> str:
    return f"{num:,}"


def print_line(char: str = "=", width: int = 64):
    print(char * width)


def print_source_stats(stats: SourceStats):
    print_line()
    print(f"规则源：{stats.name}")
    print_line("-")
    print(f"原始行数：{fmt(stats.raw_lines)}")
    print(f"跳过行数：{fmt(stats.skipped_lines)}")
    print(f"有效规则：{fmt(stats.recognized_rules)}")
    print(f"重复规则：{fmt(stats.duplicates)}")
    print(f"新增唯一：{fmt(stats.added_unique)}")
    print(f"优先级替换：{fmt(stats.replaced_by_priority)}")

    if stats.kind_counter:
        top = ", ".join(
            f"{kind}={fmt(count)}"
            for kind, count in stats.kind_counter.most_common(5)
        )
        print(f"主要类型：{top}")

    print_line()
    print()


def print_summary(aggregator: SemanticAggregator, final_rules: List[Rule]):
    kind_counter = aggregator.merged_kind_counter(final_rules)

    print_line()
    print("聚合完成")
    print_line("-")
    print(f"原始总行数：{fmt(aggregator.total_raw_lines())}")
    print(f"跳过总行数：{fmt(aggregator.total_skipped_lines())}")
    print(f"有效规则数：{fmt(aggregator.total_recognized_rules())}")
    print(f"未知保留数：{fmt(aggregator.total_unknown_kept())}")
    print(f"结构重复数：{fmt(aggregator.total_duplicates())}")
    print(f"优先级替换：{fmt(aggregator.total_replaced_by_priority())}")
    print(f"包含去重前：{fmt(aggregator.total_rules())}")
    print(f"包含去重删除：{fmt(aggregator.dropped_containment)}")
    print(f"  - DOMAIN 被后缀覆盖：{fmt(aggregator.dropped_domain_by_suffix)}")
    print(f"  - 子后缀被大后缀覆盖：{fmt(aggregator.dropped_suffix_by_suffix)}")
    print(f"  - 小网段被大网段覆盖：{fmt(aggregator.dropped_cidr_by_cidr)}")
    print(f"最终输出规则：{fmt(len(final_rules))}")

    if kind_counter:
        top = ", ".join(
            f"{kind}={fmt(count)}"
            for kind, count in kind_counter.most_common(8)
        )
        print(f"最终类型统计：{top}")

    print_line()


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

        enabled_sources.append(
            Source(
                name=item.get("name") or urlparse(url).netloc or "source",
                priority=int(item.get("priority", 0)),
                url=url,
            )
        )

    if not enabled_sources:
        print("没有启用任何规则源，请检查 config/sources.json")
        return 1

    print_line()
    print("Loon 规则聚合器")
    print_line("-")
    print(f"启用规则源：{len(enabled_sources)}")
    print(f"去重模式：{dedupe_cfg.get('mode', 'semantic')}")
    print(f"包含去重：{dedupe_cfg.get('containment', {}).get('enabled', False)}")
    print_line()
    print()

    for source in enabled_sources:
        try:
            print(f"正在拉取：{source.name}")
            text = fetch_url(source.url)
            aggregator.parse_text(text, source)
        except Exception as e:
            print(f"[警告] {source.name} 拉取或解析失败：{e}", file=sys.stderr)

    output_rel = plugin_cfg.get("output", "dist/merged-adblock.plugin")
    output_path = ROOT / output_rel
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rendered = aggregator.render(plugin_cfg)
    output_path.write_text(rendered, encoding="utf-8")

    final_rules = aggregator.all_rules()
    print_summary(aggregator, final_rules)

    print()
    print(f"完成，输出文件：{output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
