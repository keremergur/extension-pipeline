"""Results-directory lifecycle and prompt persistence.

Handles creating/resuming the timestamped run directory, deriving model
identifiers for folder names, and writing every generated prompt to disk (the
user explicitly wants all prompts saved for inspection).
"""

from datetime import datetime
from pathlib import Path

import config

from . import state
from .logging_utils import log


def get_model_identifier() -> str:
    """Short identifier used in the results folder name."""
    if config.LLM_PROVIDER == 'ollama':
        return config.OLLAMA_MODEL_PRESET
    if config.LLM_PROVIDER == 'vllm':
        # Served name may be a HF path (e.g. "meta-llama/Llama-3.1-8B-Instruct")
        # and is auto-detected only at connect time, so it can still be empty when
        # the run folder is created -- fall back to "vllm".
        name = getattr(config, 'VLLM_MODEL', '') or 'vllm'
        return name.rsplit('/', 1)[-1] or 'vllm'
    return config.LLM_PROVIDER


def get_current_model_name() -> str:
    """Full model name for display/logging."""
    providers = {
        'ollama': config.OLLAMA_MODEL,
        'vllm': getattr(config, 'VLLM_MODEL', '') or 'vllm (auto-detect at connect)',
        'openai': config.OPENAI_MODEL,
        'anthropic': config.ANTHROPIC_MODEL,
        'gemini': config.GEMINI_MODEL,
        'gemini_batch': config.GEMINI_MODEL,
    }
    return providers.get(config.LLM_PROVIDER, "unknown")


def create_results_directory() -> Path:
    """Create a fresh timestamped results directory."""
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    dir_name = f"results_{get_model_identifier()}_{timestamp}"
    results_dir = config.RESULTS_ANALYSIS_DIR / dir_name
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def get_or_create_results_directory() -> Path:
    """Return an existing directory (resume) or create a new one."""
    resume = getattr(config, 'RESUME_RUN', None)
    if not resume:
        return create_results_directory()

    if resume == "latest":
        candidates = sorted(config.RESULTS_ANALYSIS_DIR.glob("results_*"))
        if not candidates:
            raise ValueError("RESUME_RUN='latest' but no results directories found")
        results_dir = candidates[-1]
    else:
        results_dir = config.RESULTS_ANALYSIS_DIR / resume
        if not results_dir.exists():
            raise ValueError(f"RESUME_RUN directory not found: {results_dir}")

    print(f"RESUMING run: {results_dir.name}")
    return results_dir


def prompts_dir(dataset_name: str) -> Path:
    """Per-dataset subfolder where all generated prompts are written."""
    d = state.CURRENT_RESULTS_DIR / dataset_name / "prompts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_prompt(dataset_name: str, extension_id: str, label: str,
                system_prompt: str, user_message: str) -> None:
    """Write a single generated prompt to the results folder.

    `label` distinguishes stages, e.g. "single", "step1_categorize". Every
    prompt the analyzer builds is persisted here regardless of INSPECTION_MODE.
    """
    out = prompts_dir(dataset_name) / f"{extension_id}__{label}.txt"
    parts = []
    if system_prompt:
        parts.append("===== SYSTEM =====\n")
        parts.append(system_prompt.rstrip() + "\n\n")
    parts.append("===== USER =====\n")
    parts.append(user_message.rstrip() + "\n")
    try:
        out.write_text("".join(parts), encoding='utf-8')
    except Exception as e:  # never let prompt-dumping break a run
        log(f"Failed to write prompt {out.name}: {e}", "ERROR")
