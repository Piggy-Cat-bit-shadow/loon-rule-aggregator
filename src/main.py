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
    empty_lines: int = 0
    comment_lines: int = 0
    section_lines: int = 0
    recognized_rules: int = 0
    unknown_kept: int = 0
    structural_duplicates: int = 0
    unknown_duplicates: int = 0
    added_unique: int = 0
    replaced_by_priority: int = 0
    kind_counter: Counter = field(default_factory=Counter)

    @property
    def skipped_total(self) -> int:
        return self.empty_lines + self.comment_lines + self.section_lines

    @property
    def duplicate_total(self) -> int:
        return self.structural_duplicates + self.unknown_duplicates


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

            if not line:
                stats.empty_lines += 1
                continue

            skip_reason = skip_reason_of_line(line)
            if skip_reason == "comment":
                stats.comment_lines += 1
                continue
            if skip_reason == "section":
                stats.section_lines += 1
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
                    stats.unknown_duplicates += 1
                    if better(
                        rule_candidate_priority=source.priority,
                        rule_candidate_order=self.order_counter,
                        old_priority=old.priority,
                        old_order=old.order,
                    ):
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
                stats.structural_duplicates += 1
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
                covering = find_covering_suffix(host, suffixes)
                if covering is not None:
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

    def total_empty_lines(self) -> int:
        return sum(s.empty_lines for s in self.source_stats)

    def total_comment_lines(self) -> int:
        return sum(s.comment_lines for s in self.source_stats)

    def total_section_lines(self) -> int:
        return sum(s.section_lines for s in self.source_stats)

    def total_recognized_rules(self) -> int:
        return sum(s.recognized_rules for s in self.source_stats)

    def total_unknown_kept(self) -> int:
        return sum(s.unknown_kept for s in self.source_stats)

    def total_structural_duplicates(self) -> int:
        return sum(s.structural_duplicates for s in self.source_stats)

    def total_unknown_duplicates(self) -> int:
        return sum(s.unknown_duplicates for s in self.source_stats)

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
        out.append("# Generated by loon-rule-aggregator")
        out.append("# Mode: semantic dedupe, preserve original rule format")
        out.append("#")
        out.append("# Merge Summary:")
        out.append(f"# Raw lines total: {fmt(self.total_raw_lines())}")
        out.append(f"# Empty lines skipped: {fmt(self.total_empty_lines())}")
        out.append(f"# Comment lines skipped: {fmt(self.total_comment_lines())}")
        out.append(f"# Section lines skipped: {fmt(self.total_section_lines())}")
        out.append(f"# Recognized rules total: {fmt(self.total_recognized_rules())}")
        out.append(f"# Unknown kept total: {fmt(self.total_unknown_kept())}")
        out.append(f"# Structural duplicates: {fmt(self.total_structural_duplicates())}")
        out.append(f"# Unknown duplicates: {fmt(self.total_unknown_duplicates())}")
        out.append(f"# Replaced by priority: {fmt(self.total_replaced_by_priority())}")
        out.append(f"# Unique before containment: {fmt(self.total_rules())}")
        out.append(f"# Dropped by containment: {fmt(self.dropped_containment)}")
        out.append(f"#   - DOMAIN covered by DOMAIN-SUFFIX: {fmt(self.dropped_domain_by_suffix)}")
        out.append(f"#   - sub DOMAIN-SUFFIX covered by broader DOMAIN-SUFFIX: {fmt(self.dropped_suffix_by_suffix)}")
        out.append(f"#   - IP-CIDR covered by broader IP-CIDR: {fmt(self.dropped_cidr_by_cidr)}")
        out.append(f"# Final rules: {fmt(len(rules))}")
        out.append("#")
        out.append("# Final rule kinds:")
        for kind, count in kind_counter.most_common():
            out.append(f"#   - {kind}: {fmt(count)}")
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


def skip_reason_of_line(line: str) -> Optional[str]:
    if not line:
        return "empty"
    if line.startswith("#") or line.startswith("//") or line.startswith(";") or line.startswith("#!"):
        return "comment"
    if line.startswith("[") and line.endswith("]"):
        return "section"
    return None


def should_skip_line(line: str) -> bool:
    return skip_reason_of_line(line) is not None


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


def print_line(char: str = "=", width: int = 72):
    print(char * width)


def print_source_stats(stats: SourceStats):
    print_line("=")
    print(f"📥 Source: {stats.name}")
    print(f"URL: {stats.url}")
    print_line("-")
    print(f"Raw lines:                {fmt(stats.raw_lines)}")
    print(f"Skipped empty lines:      {fmt(stats.empty_lines)}")
    print(f"Skipped comments:         {fmt(stats.comment_lines)}")
    print(f"Skipped sections:         {fmt(stats.section_lines)}")
    print(f"Recognized rules:         {fmt(stats.recognized_rules)}")
    print(f"Unknown kept:             {fmt(stats.unknown_kept)}")
    print(f"Structural duplicates:    {fmt(stats.structural_duplicates)}")
    print(f"Unknown duplicates:       {fmt(stats.unknown_duplicates)}")
    print(f"Replaced by priority:     {fmt(stats.replaced_by_priority)}")
    print(f"Added unique rules:       {fmt(stats.added_unique)}")

    if stats.kind_counter:
        print("Rule kinds:")
        for kind, count in stats.kind_counter.most_common():
            print(f"  - {kind:<16} {fmt(count)}")

    print_line("=")
    print()


def print_summary(aggregator: SemanticAggregator, final_rules: List[Rule]):
    kind_counter = aggregator.merged_kind_counter(final_rules)

    print_line("=")
    print("📊 Merge Summary")
    print_line("-")
    print(f"Raw lines total:          {fmt(aggregator.total_raw_lines())}")
    print(f"Empty lines skipped:      {fmt(aggregator.total_empty_lines())}")
    print(f"Comment lines skipped:    {fmt(aggregator.total_comment_lines())}")
    print(f"Section lines skipped:    {fmt(aggregator.total_section_lines())}")
    print(f"Recognized rules total:   {fmt(aggregator.total_recognized_rules())}")
    print(f"Unknown kept total:       {fmt(aggregator.total_unknown_kept())}")
    print(f"Structural duplicates:    {fmt(aggregator.total_structural_duplicates())}")
    print(f"Unknown duplicates:       {fmt(aggregator.total_unknown_duplicates())}")
    print(f"Replaced by priority:     {fmt(aggregator.total_replaced_by_priority())}")
    print(f"Unique before contain:    {fmt(aggregator.total_rules())}")
    print(f"Containment removed:      {fmt(aggregator.dropped_containment)}")
    print(f"  - DOMAIN by suffix:     {fmt(aggregator.dropped_domain_by_suffix)}")
    print(f"  - sub suffix by suffix: {fmt(aggregator.dropped_suffix_by_suffix)}")
    print(f"  - CIDR by CIDR:         {fmt(aggregator.dropped_cidr_by_cidr)}")
    print(f"Final rules:              {fmt(len(final_rules))}")

    if kind_counter:
        print("Final rule kinds:")
        for kind, count in kind_counter.most_common():
            print(f"  - {kind:<16} {fmt(count)}")

    print_line("=")


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

    print_line("=")
    print("🚀 Loon Rule Aggregator")
    print_line("-")
    print(f"Enabled sources:          {len(enabled_sources)}")
    print(f"Dedupe mode:              {dedupe_cfg.get('mode', 'semantic')}")
    print(f"Containment dedupe:       {dedupe_cfg.get('containment', {}).get('enabled', False)}")
    print_line("=")
    print()

    for source in enabled_sources:
        try:
            print(f"Fetching {source.name} ...")
            text = fetch_url(source.url)
            aggregator.parse_text(text, source)
        except Exception as e:
            print(f"[WARN] Failed to fetch/parse {source.name}: {e}", file=sys.stderr)

    output_rel = plugin_cfg.get("output", "dist/merged-adblock.plugin")
    output_path = ROOT / output_rel
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rendered = aggregator.render(plugin_cfg)
    output_path.write_text(rendered, encoding="utf-8")

    final_rules = aggregator.all_rules()
    print_summary(aggregator, final_rules)

    print()
    print(f"✅ Done: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
