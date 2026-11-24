import re
from typing import Dict, List, Optional, Set, Tuple

import ai_provenance
import enrichment_sources
from fields import CWE_RE, meaningful, record_time
from logger import logger


def parse_cpe(cpe: str) -> Optional[Tuple[str, str, str]]:
    parts = str(cpe or '').split(':')
    if len(parts) < 6 or not parts[0].startswith('cpe'):
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if vendor in ('', '*', '-') or product in ('', '*', '-'):
        return None
    return vendor, product, version


def _key(s: str) -> str:
    return re.sub(r'[\s_-]+', '', str(s or '').lower())


def affected_from_cpes(cpes: List[str], existing: List[Dict] = None,
                       limit: int = 5) -> List[Dict]:
    seen, derived = set(), []
    for cpe in cpes or []:
        parsed = parse_cpe(cpe)
        if not parsed:
            continue
        vendor, product, version = parsed
        key = (vendor.lower(), product.lower())
        if key in seen:
            continue
        seen.add(key)
        derived.append({
            "vendor": vendor.replace('_', ' '),
            "product": product.replace('_', ' '),
            "versions": version if version not in ('*', '-', '') else "정보 없음",
            "patch_version": None,
        })
        if len(derived) >= limit:
            break
    if not derived:
        return []

    keepers = [a for a in (existing or []) if isinstance(a, dict) and meaningful(a.get('product'))]
    if not keepers:
        return derived

    by_product = {_key(d['product']): d['vendor'] for d in derived}
    vendors = {d['vendor'] for d in derived}
    sole = next(iter(vendors)) if len(vendors) == 1 else ''
    out = []
    for a in keepers:
        vendor = by_product.get(_key(a.get('product'))) or sole
        out.append({**a, "vendor": vendor} if vendor else dict(a))
    known = {_key(a.get('product')) for a in keepers}
    out.extend(d for d in derived if _key(d['product']) not in known)
    return out[:limit]


def _clip(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return (cut or text[:limit]) + "…"


_SSVC_FLAT = ("exploitation", "automatable", "technical_impact")


def flatten_ssvc(data: Dict) -> Dict:
    ssvc = data.get("ssvc")
    if not isinstance(ssvc, dict):
        return data
    for key in _SSVC_FLAT:
        value = ssvc.get(key)
        if isinstance(value, str) and value.strip():
            data[f"ssvc_{key}"] = value.strip().lower()
    return data


_CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"))


def collect_cvss(containers) -> dict:
    found = {}
    for container in containers:
        if not isinstance(container, dict):
            continue
        for metric in (container.get("metrics") or []):
            if not isinstance(metric, dict):
                continue
            for key, label in _CVSS_KEYS:
                blk = metric.get(key)
                if not isinstance(blk, dict):
                    continue
                score = blk.get("baseScore")
                if score is None:
                    continue
                try:
                    score = float(score)
                except (TypeError, ValueError):
                    continue
                found.setdefault(label, (score, blk.get("vectorString") or "N/A"))
    return found


def pick_cvss(found: dict):
    if not found:
        return 0.0, "N/A", ""
    order = {"4.0": 0, "3.1": 1, "3.0": 2}
    label = min(found, key=lambda k: (-found[k][0], order.get(k, 9)))
    return found[label][0], found[label][1], label


class Collector:
    def __init__(self):
        self.kev_loaded = False
        self.vulncheck_loaded = False
        self.kev_set: Set[str] = set()
        self.kev_ransomware: Set[str] = set()
        self.kev_due_date: Dict[str, str] = {}
        self.kev_product: Dict[str, Tuple[str, str]] = {}
        self.ai_ledger: Optional[Dict[str, Dict]] = None
        self.vulncheck_kev_set: Set[str] = set()


    def fetch_kev(self) -> bool:
        data = enrichment_sources.load_cisa_kev()
        if data is None:
            logger.error("KEV 적재 실패 — 이번 실행은 KEV 신호 없이 진행")
            return False

        self.kev_loaded = True
        self.kev_set = set(data)
        self.kev_ransomware = {
            cid for cid, item in data.items()
            if str(item.get('knownRansomwareCampaignUse', '')).strip().lower() == 'known'
        }
        self.kev_due_date = {cid: item.get('dueDate', '') for cid, item in data.items()}
        self.kev_product = {
            cid: (str(item.get('vendorProject') or '').strip(),
                  str(item.get('product') or '').strip())
            for cid, item in data.items()
        }
        logger.info(f"KEV {len(self.kev_set)}건 적재 "
                    f"(랜섬웨어 사용 확인 {len(self.kev_ransomware)}건)")
        return True


    def parse_affected(self, affected_list: List[Dict]) -> List[Dict]:
        results = []
        
        for item in affected_list:
            vendor = item.get('vendor') or 'Unknown'
            product = item.get('product') or 'Unknown'
            versions = []
            patch_version = None
            
            for v in item.get('versions', []):
                version = v.get('version', '')
                less_than = v.get('lessThan', '')
                less_than_eq = v.get('lessThanOrEqual', '')
                ver_str = ""
                
                if v.get('status') == "affected":
                    if version and version not in ["0", "n/a"]:
                        ver_str += f"{version} 부터 "
                    if less_than:
                        ver_str += f"{less_than} 이전"
                        patch_version = less_than
                    elif less_than_eq:
                        ver_str += f"{less_than_eq} 이하"
                    elif not less_than and not less_than_eq and version:
                        ver_str = f"{version} (단일 버전)"
                    
                    if not ver_str:
                        ver_str = "모든 버전"
                    
                    versions.append(ver_str.strip())
                
                elif v.get('status') in ['unaffected', 'fixed'] and version:
                    if not patch_version:
                        patch_version = version
            
            results.append({
                "vendor": vendor,
                "product": product,
                "versions": ", ".join(versions) if versions else "정보 없음",
                "patch_version": patch_version
            })
        
        return results


    def parse_record(self, cve_id: str, json_data: Dict) -> Dict:
        try:
            cna = json_data.get('containers', {}).get('cna', {})

            data = {
                "id": cve_id,
                "title": "N/A",
                "cvss": 0.0,
                "cvss_vector": "N/A",
                "cvss_version": "",
                "cvss_scores": {},
                "description": "N/A",
                "state": "UNKNOWN",
                "cwe": [],
                "references": [],
                "affected": [],
                "ssvc": {},
                "published": "",
                "assigner": "",
                "credits": [],
            }

            meta = json_data.get('cveMetadata', {}) or {}
            data['state'] = meta.get('state', 'UNKNOWN')
            data['assigner'] = str(meta.get('assignerShortName') or '').strip()
            data['published'] = str(meta.get('datePublished') or '')[:10]
            # CVE 레코드가 마지막으로 바뀐 시각 — 화면의 '갱신'. 행을 다시 저장한 시각(updated_at)과 다르다.
            data['record_updated'] = record_time(meta.get('dateUpdated'))
            data['affected'] = self.parse_affected(cna.get('affected', []))

            descriptions = cna.get('descriptions', []) or []
            en_desc = next((d.get('value') for d in descriptions
                            if (d.get('lang') or '').lower().startswith('en') and d.get('value')), None)
            if en_desc:
                data['description'] = en_desc
            elif descriptions and descriptions[0].get('value'):
                data['description'] = descriptions[0]['value']

            title = (cna.get('title') or '').strip()
            if not title:
                aff0 = next((a for a in data['affected']
                             if meaningful(a.get('product'))), None)
                if aff0:
                    vendor = (aff0.get('vendor') or '').strip()
                    product = aff0['product'].strip()
                    use_vendor = bool(meaningful(vendor)) \
                        and vendor.split()[0].lower() not in product.lower()
                    title = f"{vendor} {product} vulnerability" if use_vendor else f"{product} vulnerability"
                elif data['description'] != 'N/A':
                    title = _clip(data['description'].split('. ')[0], 110)
            data['title'] = title or 'N/A'
            
            data['cvss_scores'] = collect_cvss([cna])
            data['cvss'], data['cvss_vector'], data['cvss_version'] = \
                pick_cvss(data['cvss_scores'])
            
            for pt in cna.get('problemTypes', []):
                for desc in pt.get('descriptions', []):
                    for field in (desc.get('cweId', ''), desc.get('description', '')):
                        for m in CWE_RE.findall(str(field)):
                            if m not in data['cwe']:
                                data['cwe'].append(m)
            
            for ref in cna.get('references', []):
                if 'url' in ref:
                    data['references'].append(ref['url'])

            for credit in cna.get('credits', []) or []:
                value = str((credit or {}).get('value') or '').strip()
                if value:
                    data['credits'].append(value)

            self._enrich_from_adp(json_data, data)
            flatten_ssvc(data)

            logger.debug(f"Enriched {cve_id}: CVSS={data['cvss']}, State={data['state']}, SSVC={data['ssvc'].get('exploitation','-')}")
            return data

        except Exception as e:
            logger.error(f"{cve_id} 파싱 실패: {e}")
            return self._error_response(cve_id)


    def _enrich_from_adp(self, json_data: Dict, data: Dict) -> None:
        adp_containers = json_data.get('containers', {}).get('adp', []) or []
        for container in adp_containers:
            provider = (container.get('providerMetadata') or {}).get('shortName', '')
            if provider != 'CISA-ADP':
                continue

            for metric in container.get('metrics', []) or []:
                other = metric.get('other') or {}
                if other.get('type') == 'ssvc':
                    for opt in (other.get('content', {}) or {}).get('options', []) or []:
                        for key, val in opt.items():
                            data['ssvc'][key.lower().replace(' ', '_')] = val

            before = data['cvss']
            extra = collect_cvss([container])
            for label, val in extra.items():
                data.setdefault('cvss_scores', {}).setdefault(label, val)
            if data.get('cvss_scores'):
                data['cvss'], data['cvss_vector'], data['cvss_version'] = \
                    pick_cvss(data['cvss_scores'])
            if before == 0.0 and data['cvss'] > 0:
                logger.info(f"  ADP CVSS 보강: {data['id']} → {data['cvss']} "
                            f"(v{data.get('cvss_version') or '?'})")

            if not data['cwe']:
                for pt in container.get('problemTypes', []) or []:
                    for desc in pt.get('descriptions', []) or []:
                        cwe_id = desc.get('cweId', '')
                        if cwe_id:
                            data['cwe'].append(cwe_id)


    def fetch_vulncheck_kev(self) -> bool:
        data = enrichment_sources.load_vulncheck_kev()
        if data is None:
            return False
        self.vulncheck_loaded = True
        self.vulncheck_kev_set = set(data)
        logger.info(f"VulnCheck KEV {len(self.vulncheck_kev_set)}건 적재")
        return True


    def enrich_cheap_signals(self, cve_data: Dict) -> Dict:
        cve_id = cve_data['id']
        if self.vulncheck_loaded:
            cve_data['is_vulncheck_kev'] = cve_id in self.vulncheck_kev_set
        if self.kev_loaded:
            cve_data['is_kev_ransomware'] = cve_id in self.kev_ransomware
        if enrichment_sources.exploitdb_ok():
            edb_entry = enrichment_sources.exploitdb_entry(cve_id)
            cve_data['has_public_exploit'] = edb_entry is not None
            if edb_entry and edb_entry[1]:
                cve_data['_exploit_db_url'] = f"https://www.exploit-db.com/exploits/{edb_entry[1]}"
        if enrichment_sources.metasploit_ok():
            msf_modules = enrichment_sources.metasploit_modules(cve_id)
            cve_data['has_metasploit_module'] = bool(msf_modules)
            cve_data['metasploit_modules'] = [m['fullname'] for m in msf_modules[:3]]
            if msf_modules:
                logger.info(f"  🧨 Metasploit 모듈: {cve_id} ({len(msf_modules)}개, 최고 rank={msf_modules[0]['rank_name']})")
        if enrichment_sources.poc_ok():
            urls = enrichment_sources.poc_urls(cve_id)
            cve_data['has_poc'] = bool(urls)
            cve_data['poc_urls'] = urls
        if enrichment_sources.nuclei_ok():
            tpl = enrichment_sources.nuclei_template(cve_id)
            cve_data['has_nuclei_template'] = tpl is not None
            if tpl:
                cve_data['nuclei_severity'] = tpl.get('severity', '')
                cve_data['_nuclei_url'] = enrichment_sources.nuclei_template_url(tpl.get('path', ''))
                logger.info(f"  🎯 nuclei 템플릿: {cve_id} ({tpl.get('severity', '?')})")
        prov = ai_provenance.detect(cve_id, cve_data.get('credits'), self.ai_ledger)
        if prov:
            cve_data.update(prov.as_state())
            logger.info(f"  🤖 AI 발견: {cve_id} ({prov.program}) — {prov.detail[:80]}")
        elif self.ai_ledger is not None:
            cve_data['ai_discovered'] = False
        self.fill_product_from_kev(cve_data)
        return cve_data


    def fill_product_from_kev(self, cve_data: Dict) -> Dict:
        vendor, product = self.kev_product.get(cve_data.get('id'), ('', ''))
        affected = cve_data.get('affected') or []
        usable = any(meaningful(a.get('product')) for a in affected if isinstance(a, dict))
        if not product:
            if not self.kev_loaded and not usable:
                cve_data.pop('affected', None)
            return cve_data
        if usable:
            return cve_data
        cve_data['affected'] = [{
            "vendor": vendor or "Unknown",
            "product": product,
            "versions": affected[0].get('versions') if affected else "정보 없음",
            "patch_version": affected[0].get('patch_version') if affected else None,
            "source": "CISA KEV",
        }]
        return cve_data


    def _error_response(self, cve_id: str, state: str = "ERROR") -> Dict:
        return {
            "id": cve_id,
            "title": "Error",
            "cvss": 0.0,
            "cvss_vector": "N/A",
            "cvss_version": "",
            "cvss_scores": {},
            "description": "Error",
            "state": state,
            "cwe": [],
            "references": [],
            "affected": []
        }
