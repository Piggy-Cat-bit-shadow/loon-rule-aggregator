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


DEFAULT_USER_AGENT = "Loon/3.2.0 CFNetwork/1496.0.7 Darwin/23.5.0"

REJECT_POLICIES = {
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
}


@dataclass(frozen=True)
class Source:
    name: str
    priority: int
    url: str
    user_agent: str = ""


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
        kind = self.kind.upper()
        policy = normalize_policy(self.policy)
        target = normalize_target_by_kind(kind, self.target)

        if policy == "REJECT":
            options = ()
        else:
            options = tuple(x.lower().strip() for x in self.options)

        return kind, target, policy, options


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

        self._cached_final_rules: Optional[List[Rule]] = None

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
        self._cached_final_rules = None
        print_source_stats(stats)

    def total_rules(self) -> int:
        return len(self.rules_by_key) + len(self.unknown_by_key)

    def all_rules(self) -> List[Rule]:
        if self._cached_final_rules is not None:
            return self._cached_final_rules

        rules = list(self.rules_by_key.values()) + list(self.unknown_by_key.values())

        if self.dedupe_cfg.get("containment", {}).get("enabled", False):
            rules = self.apply_containment_dedupe(rules)

        self._cached_final_rules = rules
        return rules

    def apply_containment_dedupe(self, rules: List[Rule]) -> List[Rule]:
        self.dropped_containment = 0
        self.dropped_domain_by_suffix = 0
        self.dropped_suffix_by_suffix = 0
        self.dropped_cidr_by_cidr = 0

        cfg = self.dedupe_cfg.get("containment", {})
        remove_ids = set()

        suffix_rules: List[Tuple[str, Rule]] = []
        domain_rules: List[Tuple[str, Rule]] = []

        for r in rules:
            kind = r.kind.upper()
            policy = normalize_policy(r.policy)

            if policy != "REJECT":
                continue

            if kind == "DOMAIN-SUFFIX":
                host = normalize_domain(r.target)
                if host:
                    suffix_rules.append((host, r))

            elif kind == "DOMAIN":
                host = normalize_domain(r.target)
                if host:
                    domain_rules.append((host, r))

        suffix_set = {host for host, _ in suffix_rules}

        if cfg.get("domain_suffix_contains_domain", True):
            for host, r in domain_rules:
                if has_covering_suffix(host, suffix_set):
                    remove_ids.add(id(r))
                    self.dropped_domain_by_suffix += 1

        if cfg.get("domain_suffix_contains_sub_suffix", True):
            for host, r in suffix_rules:
                if has_parent_suffix(host, suffix_set):
                    remove_ids.add(id(r))
                    self.dropped_suffix_by_suffix += 1

        if cfg.get("ip_cidr_contains", True):
            cidr_rules = [
                r for r in rules
                if r.kind.upper() in {"IP-CIDR", "IP-CIDR6"}
                and normalize_policy(r.policy) == "REJECT"
            ]

            networks_v4: List[Tuple[ipaddress._BaseNetwork, Rule]] = []
            networks_v6: List[Tuple[ipaddress._BaseNetwork, Rule]] = []

            for r in cidr_rules:
                try:
                    net = ipaddress.ip_network(r.target, strict=False)
                    if net.version == 4:
                        networks_v4.append((net, r))
                    else:
                        networks_v6.append((net, r))
                except Exception:
                    pass

            self._mark_covered_cidr(networks_v4, remove_ids)
            self._mark_covered_cidr(networks_v6, remove_ids)

        self.dropped_containment = len(remove_ids)
        return [r for r in rules if id(r) not in remove_ids]

    def _mark_covered_cidr(self, networks: List[Tuple[ipaddress._BaseNetwork, Rule]], remove_ids: set):
        networks.sort(key=lambda x: x[0].prefixlen)

        parents: List[Tuple[ipaddress._BaseNetwork, Rule]] = []

        for net, r in networks:
            covered = False

            for parent_net, parent_rule in parents:
                if id(parent_rule) == id(r):
                    continue
                if parent_net.prefixlen >= net.prefixlen:
                    continue
                if net.subnet_of(parent_net):
                    covered = True
                    break

            if covered:
                if id(r) not in remove_ids:
                    remove_ids.add(id(r))
                    self.dropped_cidr_by_cidr += 1
            else:
                parents.append((net, r))

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

        out.append("# 由 loon-rule-aggregator 自动生成")
        out.append("# 类型：Loon / Surge 纯规则列表")
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
        out.append("# 最终规则类型：")

        for kind, count in kind_counter.most_common():
            out.append(f"# - {kind}: {fmt(count)}")

        out.append("")

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


def normalize_policy(policy: str) -> str:
    p = policy.strip().upper()

    if p in REJECT_POLICIES:
        return "REJECT"

    return p


def normalize_target_by_kind(kind: str, target: str) -> str:
    kind = kind.upper()

    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return normalize_domain(target)

    if kind in {"IP-CIDR", "IP-CIDR6"}:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except Exception:
            return target.strip().lower()

    return normalize_target(target)


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
    d = domain.strip().lower()
    d = d.rstrip(".")
    d = d.lstrip("*.")
    d = d.lstrip(".")
    d = re.sub(r"\.+", ".", d)

    if not d or "/" in d or ":" in d:
        return ""

    return d


def iter_parent_suffixes(domain: str):
    parts = normalize_domain(domain).split(".")

    for i in range(1, len(parts)):
        yield ".".join(parts[i:])


def has_parent_suffix(domain: str, suffix_set: set) -> bool:
    domain = normalize_domain(domain)

    for parent in iter_parent_suffixes(domain):
        if parent in suffix_set:
            return True

    return False


def has_covering_suffix(domain: str, suffix_set: set) -> bool:
    domain = normalize_domain(domain)

    if domain in suffix_set:
        return True

    for parent in iter_parent_suffixes(domain):
        if parent in suffix_set:
            return True

    return False


def fetch_url(url: str, user_agent: str = "") -> str:
    ua = user_agent or DEFAULT_USER_AGENT

    print(f"使用 UA：{ua}")

    headers = {
        "User-Agent": ua,
        "Accept": "*/*",
        "Connection": "keep-alive",
    }

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
                user_agent=item.get("user_agent", ""),
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
            text = fetch_url(source.url, source.user_agent)
            aggregator.parse_text(text, source)
        except Exception as e:
            print_line("!")
            print(f"拉取失败：{source.name}")
            print(f"地址：{source.url}")
            print(f"错误：{repr(e)}")
            print_line("!")

    output_rel = plugin_cfg.get("output", "dist/merged-adblock.list")
    output_path = ROOT / output_rel
    output_path.parent.mkdir(parents=True, exist_ok=True)

    final_rules = aggregator.all_rules()
    rendered = aggregator.render(plugin_cfg)
    output_path.write_text(rendered, encoding="utf-8")

    print_summary(aggregator, final_rules)

    print()
    print(f"完成，输出文件：{output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
