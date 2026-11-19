from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple


class StoreError(Exception):
    pass


class Store(ABC):

    @abstractmethod
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        raise NotImplementedError

    @abstractmethod
    def get_cves(self, cve_ids) -> Tuple[Dict[str, Dict], Set[str]]:
        raise NotImplementedError

    @abstractmethod
    def upsert_cve(self, data: Dict) -> bool:
        raise NotImplementedError

    @abstractmethod
    def bulk_save_states(self, updates: List[Dict], label: str = "상태") -> int:
        raise NotImplementedError

    @abstractmethod
    def patch_states(self, updates: List[Dict], label: str = "상태") -> int:
        """저장된 상태에서 일부 키만 바꾼다 — updates 는 {"id", "patch": {키: 값}, (그 밖의 열)}.

        상태를 읽고 → 오래 걸리는 일을 하고 → 통째로 다시 쓰면 그 사이 fast-lane 이 바꾼 값
        (발화 이력 · 등급 · KEV)이 옛 값으로 되돌아간다. 백필은 자기가 만든 키만 쓴다.
        """
        raise NotImplementedError

    @abstractmethod
    def count_tracked(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_tracked_ids(self) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def get_rows_missing_vendor(self) -> List[Dict]:
        raise NotImplementedError

    @abstractmethod
    def get_rows_needing_cvss(self) -> List[Dict]:
        raise NotImplementedError

    @abstractmethod
    def get_translation_backfill_candidates(self, limit: int = 60,
                                            offset: int = 0) -> List[Dict]:
        raise NotImplementedError

    @abstractmethod
    def update_translation(self, cve_id: str, title_ko: str, desc_ko: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_missing_report_candidates(self, limit: int = 20) -> List[Dict]:
        raise NotImplementedError

    @abstractmethod
    def count_missing_reports(self) -> Dict[str, int]:
        raise NotImplementedError

    @abstractmethod
    def get_rule_recheck_candidates(self, limit: int = 10) -> List[Dict]:
        raise NotImplementedError

    @abstractmethod
    def get_rule_rows(self, cve_ids, days: int = 90) -> Dict[str, Dict]:
        raise NotImplementedError

    @abstractmethod
    def get_pipeline_state(self) -> Dict:
        raise NotImplementedError

    @abstractmethod
    def set_pipeline_state(self, state: Dict) -> bool:
        raise NotImplementedError

    @abstractmethod
    def request_full_export(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_snapshot_digest(self, source: str) -> Optional[str]:
        raise NotImplementedError

    @abstractmethod
    def get_snapshot_ids(self, source: str) -> Set[str]:
        raise NotImplementedError

    @abstractmethod
    def save_snapshot(self, source: str, digest: str, ids) -> bool:
        raise NotImplementedError

    @abstractmethod
    def take_full_export_flag(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def has_full_export_flag(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def clear_full_export_flag(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def export_rows(self, since: Optional[str], days: int = 90) -> List[Dict]:
        raise NotImplementedError

    @abstractmethod
    def live_ids(self, days: int = 90) -> Set[str]:
        raise NotImplementedError

    @abstractmethod
    def count_rows(self, tracked: bool = False) -> int:
        raise NotImplementedError

    @abstractmethod
    def retention_rows(self, before: str, limit: int, *, tracked: bool = False,
                       unalerted: bool = False, oldest_first: bool = False,
                       offset: int = 0) -> List[Dict]:
        raise NotImplementedError

    @abstractmethod
    def delete_markers(self, before: str, limit: int) -> int:
        raise NotImplementedError

    @abstractmethod
    def blank_states(self, ids) -> int:
        raise NotImplementedError

    @abstractmethod
    def delete_rows(self, ids) -> int:
        raise NotImplementedError
