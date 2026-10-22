import os
import sys


class ConfigError(Exception):
    pass


_TRANSLATION_CHAIN = (
    ("gemma-4-31b-it", "gemma_31b"),
    ("gemma-4-26b-a4b-it", "gemma_26b"),
    ("gemini-3.1-flash-lite", "gemini_31"),
    ("gemini-3.5-flash-lite", "gemini_35"),
)


def _translation_chain():
    only = (os.environ.get("ARGUS_TRANSLATION_MODELS") or "").strip().lower()
    if not only:
        return _TRANSLATION_CHAIN
    picked = tuple(p for p in _TRANSLATION_CHAIN if p[1].startswith(only))
    if not picked:
        raise ConfigError(f"ARGUS_TRANSLATION_MODELS={only!r} 에 맞는 모델이 없다. "
                          f"쓸 수 있는 값: "
                          f"{', '.join(sorted({k.split('_')[0] for _m, k in _TRANSLATION_CHAIN}))}")
    return picked


class ArgusConfig:
    TRANSLATION_MODELS = _TRANSLATION_CHAIN

    ANALYSIS_MODELS = (
        ("gemini-3.5-flash-lite", "gemini_35"),
        ("gemini-3.1-flash-lite", "gemini_31"),
    )

    ANALYSIS_PARAMS = {
        "temperature": 0.3,
        "top_p": 0.9,
        "max_output_tokens": 4096,
    }

    PERFORMANCE = {
        "max_workers": 4,

        "fast_max_changes": 1500,
        "fast_deadline_minutes": 5,
        "snapshot_cap": 80,

        "bulk_deadline_minutes": 38,
        "translation_batch_size": 6,
        "translation_concurrency": 4,
        "translation_backfill_pool": 200,

        "translation_minutes": int(os.environ.get("ARGUS_TRANSLATION_MINUTES", "18")),
        "translation_daily_reserve": 0.15,

        "analysis_per_run": 100,
        "max_rule_recheck": 10,
        "max_rule_refresh": 30,

        "max_consecutive_failures": 3,
        "quarantine_retry_hours": 24,
    }

    REQUIRED_ENV_VARS = [
        "GH_TOKEN",
        "SLACK_WEBHOOK_URL",
        "GEMINI_API_KEY"
    ]

    STORE_ENV_VARS = {
        "turso": ["TURSO_DATABASE_URL", "TURSO_AUTH_TOKEN"],
    }


    def __init__(self):
        self._validate_environment()
        self.TRANSLATION_MODELS = _translation_chain()


    def required_env_vars(self):
        store = (os.environ.get("ARGUS_STORE") or "turso").strip().lower()
        return self.REQUIRED_ENV_VARS + self.STORE_ENV_VARS.get(store, [])


    def _validate_environment(self):
        missing = []

        for var in self.required_env_vars():
            value = os.environ.get(var)
            if not value or value.strip() == "":
                missing.append(var)
        
        if missing:
            error_msg = f"""
❌ 필수 환경 변수가 설정되지 않았습니다:
{chr(10).join(f'  - {var}' for var in missing)}

GitHub Actions Secrets에 다음 변수들을 추가해주세요.
"""
            raise ConfigError(error_msg)


try:
    config = ArgusConfig()
except ConfigError as e:
    print(f"\n{e}\n")
    sys.exit(1)
