"""LLM client setup and structured-output querying.

The pipelines call `query_structured(...)`: they hand it a system prompt, a user
message, and a JSON schema, and get back a parsed dict that conforms to that
schema. Each provider's native structured-output mechanism is used so the prompts
no longer need to beg the model for valid JSON.

`query_structured_ex(...)` is the same call with two extra return values: how sure
the model was of one enum field (e.g. the TP/FP/NA verdict) as a scalar, and the
full per-label probability distribution behind it, both read from the token
logprobs rather than from anything the model writes about itself. Only providers
that expose logprobs (vllm/openai) can measure them; elsewhere they return None.

Ollama is the primary target and can be reached two ways (see setup_llm_client):
  * directly over http://HOST:PORT (Ollama exposed on another server), or
  * through an SSH tunnel (legacy).
An OpenAI/Anthropic/Gemini API can be swapped in later via config.LLM_PROVIDER.
"""

import json
import math
import random
import re
import threading
import time

import requests

import config

from .token_bucket import TokenBucket

# Lazily-imported SDKs (only the configured provider is imported).
if config.LLM_PROVIDER == 'openai':
    from openai import OpenAI
elif config.LLM_PROVIDER == 'anthropic':
    import anthropic
elif config.LLM_PROVIDER in ('gemini', 'gemini_batch'):
    from google import genai

_token_bucket = TokenBucket()

# Per-thread diagnostics from the most recent call, read by the pipeline right
# after query_structured_ex returns. Thread-local because PARALLEL>1 runs several
# findings concurrently and a module global would interleave.
_diag = threading.local()


def last_call_diagnostics() -> dict:
    """Diagnostics for this thread's most recent structured query.

    Keys (all optional):
      completion_tokens / prompt_tokens -- from the provider's usage block. With a
        reasoning parser the completion count INCLUDES the thinking trace, so this
        is how long the model actually thought.
      logprob_censored -- True when at least one allowed label was missing from
        top_logprobs. The probe then cannot see the runner-up and reports the
        winner as exactly 1.0; the real value is only "at least" that (see
        logprob_floor). 57% of one qwen-parser run was censored this way.
      logprob_floor -- exp() of the smallest logprob actually returned at the
        verdict position, i.e. the measurement floor: a missing label's true
        probability is somewhere below this, not zero.
      logprob_raw_total -- summed probability of the allowed labels BEFORE
        renormalisation. Near 1.0 means the server masked to the grammar; well
        below 1.0 means the logprobs are the unconstrained distribution.
      extra_confidence -- {field: {"confidence": p, "dist": {...}, "censored": bool}}
        for every `extra_logprob_fields` entry of the call. This is how a pipeline
        that decides TWO enums in ONE response (single_vulnerability: `result` and
        `attacker_source`) reads the second one; the multi pipeline measures each in
        its own call and never sets it. Returned out-of-band rather than as a fourth
        return value so every existing caller of query_structured_ex is untouched.
    """
    return dict(getattr(_diag, "data", {}) or {})


def _set_diag(**kw):
    d = dict(getattr(_diag, "data", {}) or {})
    d.update(kw)
    _diag.data = d


def estimate_token_count(text: str) -> int:
    """Rough token estimate (~3 chars/token for code-heavy prompts)."""
    return len(text) // 3


# ---- client setup ------------------------------------------------------

def setup_llm_client():
    """Initialize the client. Returns (tunnel_or_None, client_handle).

    For Ollama the client_handle is a base URL string; for the SDK providers it
    is the SDK client object.
    """
    if config.LLM_PROVIDER == 'ollama':
        if getattr(config, 'OLLAMA_USE_SSH_TUNNEL', False):
            tunnel = _setup_ssh_tunnel()
            base_url = f"http://127.0.0.1:{tunnel.local_bind_port}"
            print(f"SSH tunnel: {base_url}")
            return tunnel, base_url
        base_url = f"http://{config.OLLAMA_HOST}:{config.OLLAMA_PORT}"
        print(f"Ollama endpoint: {base_url}")
        return None, base_url

    if config.LLM_PROVIDER == 'vllm':
        base_url = f"http://{config.VLLM_HOST}:{config.VLLM_PORT}"
        model = _resolve_vllm_model(base_url)
        print(f"vLLM endpoint: {base_url} (model: {model})")
        return None, base_url

    if config.LLM_PROVIDER == 'openai':
        print("OpenAI initialized")
        return None, OpenAI(api_key=config.OPENAI_API_KEY)

    if config.LLM_PROVIDER == 'anthropic':
        print("Anthropic initialized")
        return None, anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    if config.LLM_PROVIDER in ('gemini', 'gemini_batch'):
        print(f"Google Gemini initialized ({config.GEMINI_MODEL})")
        return None, genai.Client(api_key=config.GEMINI_API_KEY)

    raise ValueError(f"Unknown provider: {config.LLM_PROVIDER}")


def _resolve_vllm_model(base_url: str) -> str:
    """Return the model name to send in each request.

    A vLLM server serves one model chosen at launch, so the request's `model`
    field must match it. If VLLM_MODEL is set we trust it; otherwise we look it up
    from the server's /v1/models list (taking the first entry) and cache it back
    onto config so the results folder name and request payloads can reuse it.
    """
    if getattr(config, 'VLLM_MODEL', ''):
        return config.VLLM_MODEL
    headers = {}
    if getattr(config, 'VLLM_API_KEY', ''):
        headers["Authorization"] = f"Bearer {config.VLLM_API_KEY}"
    try:
        resp = requests.get(f"{base_url}/v1/models", headers=headers, timeout=30)
        resp.raise_for_status()
        models = resp.json().get("data", [])
        model_id = models[0]["id"] if models else None
    except Exception as e:
        raise LLMError(
            f"Could not auto-detect the vLLM model from {base_url}/v1/models ({e}); "
            "set VLLM_MODEL explicitly."
        )
    if not model_id:
        raise LLMError(f"vLLM at {base_url} reports no served models; set VLLM_MODEL.")
    config.VLLM_MODEL = model_id  # cache for request payloads + folder/display naming
    return model_id


def _setup_ssh_tunnel():
    from sshtunnel import SSHTunnelForwarder
    tunnel = SSHTunnelForwarder(
        (config.OLLAMA_SSH_HOST, config.OLLAMA_SSH_PORT),
        ssh_username=config.OLLAMA_SSH_USER,
        ssh_password=config.OLLAMA_SSH_PASSWORD,
        remote_bind_address=('127.0.0.1', 11434),
        local_bind_address=('127.0.0.1', 0),
        allow_agent=False,
        host_pkey_directories=[],
    )
    tunnel.start()
    return tunnel


# ---- structured querying -----------------------------------------------

class LLMError(Exception):
    """Raised when a structured query cannot produce a conforming result."""


def query_structured(system_prompt: str, user_message: str, schema: dict, client) -> dict:
    """Query the configured provider and return a parsed dict matching `schema`."""
    result, _, _ = query_structured_ex(system_prompt, user_message, schema, client)
    return result


def supports_logprobs() -> bool:
    """True when the configured provider can return per-token logprobs."""
    return config.LLM_PROVIDER in ('vllm', 'openai')


def query_structured_ex(system_prompt: str, user_message: str, schema: dict, client,
                        logprob_field: str = None, logprob_values=None,
                        temperature=None, seed_offset=0, thinking_budget=None,
                        frequency_penalty=None, extra_logprob_fields=None):
    """Structured query that can also measure how sure the model was.

    Args:
        logprob_field: name of the schema field whose verdict token should be
            measured (e.g. "result"). When given -- and the provider supports
            logprobs -- the response's token logprobs are inspected.
        logprob_values: the allowed values of that field (e.g. ["TP","FP","NA"]);
            the probability is normalised over just these, so it answers "how sure
            was the model of THIS verdict against the other verdicts".
        extra_logprob_fields: further (field, allowed_values) pairs to measure from
            the SAME response, read back via last_call_diagnostics()["extra_confidence"].
            Needed only by a pipeline whose one call decides several enums
            (single_vulnerability); the return signature is unchanged so that no
            existing caller has to know about it.
        temperature: per-call sampling temperature override (None = config default).
            Used to draw diverse self-consistency votes without changing the global
            temperature that categorize/payload run at.
        seed_offset: added to VLLM_SEED so repeated votes at temperature > 0 are
            diverse rather than identical when a base seed is pinned.
        thinking_budget: per-call `thinking_token_budget` override (None = config
            default, shared with every other call). vLLM-only; ignored by other
            providers. See config.payload_thinking_budget().

    Returns (result_dict, confidence, dist) where `confidence` is the chosen label's
    probability (float 0..1) or None, and `dist` is the full {LABEL: prob} map or
    None. Both are None when no logprob signal could be measured (unsupported
    provider, or the token was not located); callers treat that as "no signal".
    """
    provider = config.LLM_PROVIDER
    want = bool(logprob_field and logprob_values)
    if provider == 'ollama':
        return _ollama_structured(system_prompt, user_message, schema, client), None, None
    if provider == 'vllm':
        return _vllm_structured(system_prompt, user_message, schema, client,
                                logprob_field if want else None, logprob_values,
                                temperature=temperature, seed_offset=seed_offset,
                                thinking_budget=thinking_budget,
                                frequency_penalty=frequency_penalty,
                                extra_logprob_fields=extra_logprob_fields)
    if provider == 'openai':
        return _openai_structured(system_prompt, user_message, schema, client), None, None
    if provider == 'anthropic':
        return _anthropic_structured(system_prompt, user_message, schema, client), None, None
    if provider == 'gemini':
        return _gemini_structured(system_prompt, user_message, schema, client), None, None
    if provider == 'gemini_batch':
        raise LLMError("gemini_batch does not support interactive structured queries; "
                       "use PIPELINE_MODE='single' with batch handling.")
    raise LLMError(f"Unknown provider: {provider}")


def _ollama_structured(system_prompt, user_message, schema, base_url) -> dict:
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})

    response = requests.post(
        f"{base_url}/api/chat",
        json={
            "model": config.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "format": schema,  # Ollama constrains output to this JSON schema
            # Hold the model (and its prompt cache) in memory between calls --
            # an unload throws the cached prefix away. See PROMPT_CACHE_OPTIMIZED
            # for how the prompts themselves are laid out for that cache.
            "keep_alive": getattr(config, 'OLLAMA_KEEP_ALIVE', '5m'),
            "options": {
                "temperature": getattr(config, 'OLLAMA_TEMPERATURE', 0),
                # Avoid silent truncation of large report+code prompts.
                "num_ctx": getattr(config, 'OLLAMA_NUM_CTX', 8192),
            },
        },
        timeout=config.OLLAMA_TIMEOUT,
    )
    response.raise_for_status()
    content = response.json().get("message", {}).get("content", "")
    try:
        return _parse_json(content)
    except LLMError:
        # The response ignored the JSON schema (free-form prose). This means the
        # server did not enforce structured output -- almost always an Ollama
        # older than 0.5.0, or a non-native (OpenAI-compat) endpoint. Surface it.
        raise LLMError(
            "Ollama returned unstructured output despite a 'format' schema. "
            "Upgrade the server to Ollama >= 0.5.0 (native /api/chat structured "
            f"outputs). First 200 chars: {content[:200]!r}"
        )


def _vllm_structured(system_prompt, user_message, schema, base_url,
                     logprob_field=None, logprob_values=None,
                     temperature=None, seed_offset=0, thinking_budget=None,
                     frequency_penalty=None, extra_logprob_fields=None):
    """Query a vLLM OpenAI-compatible server with schema-constrained output.

    Uses raw HTTP (no SDK dependency, mirroring the Ollama path). Structured
    output is requested per config.VLLM_STRUCTURED_MODE -- either the OpenAI-style
    response_format json_schema or vLLM's native guided_json. VLLM_SEED, when set,
    goes on the request for reproducible sampling (+ seed_offset so a fixed seed
    still yields diverse self-consistency votes).

    thinking_budget: per-call override for the request's `thinking_token_budget`
        (None = use config.VLLM_THINKING_TOKEN_BUDGET, i.e. every call shares one
        run-wide budget, as before this parameter existed). Callers that need a
        step-specific cap -- currently just the payload step via
        config.payload_thinking_budget() -- resolve their own value and pass it in.

    frequency_penalty: per-call override for the request's `frequency_penalty`
        (None = use config.VLLM_FREQUENCY_PENALTY, which is 0/off by default). A
        retry of a candidate that hit a repetition loop can pass a nonzero value
        here without perturbing any other call -- see EXPERIMENTS.md 48-52.

    Returns (parsed_dict, confidence, dist). `confidence` is the normalised
    probability of the emitted `logprob_field` value and `dist` the full per-label
    map, when that measurement was requested and possible, else both None.
    """
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})

    payload = {
        # A vLLM server serves one model; the request must name it. _resolve_vllm_model
        # cached it onto config at setup (auto-detected when VLLM_MODEL was empty).
        "model": config.VLLM_MODEL,
        "messages": messages,
        "stream": False,
        "temperature": (getattr(config, 'VLLM_TEMPERATURE', 0)
                        if temperature is None else temperature),
        "top_p": getattr(config, 'VLLM_TOP_P', 1.0),
        "max_tokens": getattr(config, 'VLLM_MAX_TOKENS', 2048),
    }
    seed = getattr(config, 'VLLM_SEED', None)
    if seed is not None:
        payload["seed"] = seed + int(seed_offset)

    # Cap the <think> trace so it cannot eat the whole max_tokens budget and leave
    # no room for the JSON (that failure returns content=null; see below). Omitted
    # from the request when unset, so a run without it is byte-identical to before.
    think_budget = (getattr(config, 'VLLM_THINKING_TOKEN_BUDGET', None)
                    if thinking_budget is None else thinking_budget)
    if think_budget is not None:
        payload["thinking_token_budget"] = int(think_budget)

    # Break degenerate repetition loops (EXPERIMENTS.md 48-52). Same omit-when-unset
    # rule as thinking_token_budget above: at 0 the field never reaches the server, so
    # a default run is byte-identical to one made before this existed.
    freq_penalty = (getattr(config, 'VLLM_FREQUENCY_PENALTY', 0.0)
                    if frequency_penalty is None else frequency_penalty)
    if freq_penalty:
        payload["frequency_penalty"] = float(freq_penalty)

    if getattr(config, 'VLLM_STRUCTURED_MODE', 'response_format') == 'guided_json':
        payload["guided_json"] = schema  # vLLM native extra field
    else:
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "analysis_result", "schema": schema},
        }
    backend = getattr(config, 'VLLM_GUIDED_BACKEND', '')
    if backend:
        payload["guided_decoding_backend"] = backend

    if logprob_field or extra_logprob_fields:
        # Ask for alternatives at every position; the verdict token's alternatives
        # are what the confidence is normalised over.
        payload["logprobs"] = True
        payload["top_logprobs"] = int(getattr(config, 'LOGPROBS_TOP_N', 20))

    headers = {}
    if getattr(config, 'VLLM_API_KEY', ''):
        headers["Authorization"] = f"Bearer {config.VLLM_API_KEY}"

    response = requests.post(
        f"{base_url}/v1/chat/completions",
        json=payload, headers=headers, timeout=config.VLLM_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()
    try:
        choice = data["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise LLMError(f"Unexpected vLLM response shape: {str(data)[:200]}")
    try:
        parsed = _parse_json(content)
    except LLMError:
        # Schema was ignored -> guided decoding likely not active on the server, or
        # generation was cut off before the JSON closed (raise VLLM_MAX_TOKENS).
        finish = choice.get("finish_reason")
        if content is None:
            # A reasoning parser was active and the model never closed </think>:
            # vLLM routed the whole completion to `reasoning_content` and left
            # `content` null, so there is no answer to parse. The trace spent the
            # entire max_tokens budget; cap it with VLLM_THINKING_TOKEN_BUDGET (or
            # raise VLLM_MAX_TOKENS). NOTE: `content` being None used to reach the
            # slice below and raise a bare TypeError("'NoneType' object is not
            # subscriptable"), which hid this diagnosis -- see EXPERIMENTS.md 35.
            reasoning = (choice.get("message") or {}).get("reasoning_content") or ""
            raise LLMError(
                "vLLM returned no content: the reasoning trace consumed the whole "
                f"output budget without closing the thinking block (finish_reason="
                f"{finish!r}, reasoning_content {len(reasoning)} chars). Set "
                "VLLM_THINKING_TOKEN_BUDGET below VLLM_MAX_TOKENS, or raise "
                "VLLM_MAX_TOKENS."
            )
        hint = (" The response hit the token limit (finish_reason='length'); raise "
                "VLLM_MAX_TOKENS." if finish == "length" else
                " Ensure guided decoding is available and try "
                "VLLM_STRUCTURED_MODE='guided_json' (or set VLLM_GUIDED_BACKEND).")
        raise LLMError(
            f"vLLM returned unparseable output despite a schema.{hint} "
            f"First 200 chars: {content[:200]!r}"
        )

    usage = data.get("usage") or {}
    _set_diag(prompt_tokens=usage.get("prompt_tokens"),
              completion_tokens=usage.get("completion_tokens"),
              logprob_censored=None, logprob_missing=None,
              logprob_floor=None, logprob_raw_total=None, logprob_topn=None,
              # Cleared per call, or a candidate whose response carried no
              # attacker_source would inherit the previous one's measurement.
              extra_confidence=None)

    entries = (choice.get("logprobs") or {}).get("content") or []

    def measure(field, values):
        """(confidence, dist) for one enum field of this response."""
        d = _verdict_confidence(entries, field, values)
        if not d:
            return None, None
        chosen = str(parsed.get(field, "")).strip().upper()
        return d.get(chosen, max(d.values())), d

    confidence, dist = (measure(logprob_field, logprob_values)
                        if logprob_field else (None, None))

    if extra_logprob_fields:
        # _verdict_confidence writes the censoring diagnostics of whichever field it
        # last looked at, so snapshot the primary field's before measuring the others
        # and restore it afterwards -- each extra field carries its own `censored`
        # flag instead of overwriting the one the trace records.
        primary_diag = last_call_diagnostics()
        extras = {}
        for field, values in extra_logprob_fields:
            conf, d = measure(field, values)
            extras[field] = {"confidence": conf, "dist": d,
                             "censored": last_call_diagnostics().get("logprob_censored")}
        _diag.data = dict(primary_diag)
        _set_diag(extra_confidence=extras)

    return parsed, confidence, dist


def _verdict_confidence(token_entries, field, values):
    """Per-label probability distribution for `field`, normalised over `values`.

    Returns a dict {LABEL: prob} (summing to ~1 over `values`) or None when the
    verdict token cannot be located. The chosen label's entry is the scalar
    confidence; the whole dict feeds confidence_tp / confidence_fp / confidence_na.

    Locating the right token is the whole difficulty, and it must not assume
    anything about tokenisation:

      * The KEY may span several tokens. "result" happens to be one token, but
        "attacker_source" is typically split ("attacker" + "_source"), so scanning
        for a single token that contains the field name silently finds nothing.
        Instead the decoded text is reassembled and the JSON key is located with a
        regex over that text, then mapped back to the token covering the value.
      * The VALUE may also be split ("N" + "A"). Since the allowed labels differ in
        their first character, the first value token already identifies the label,
        so a prefix match is enough.
      * Matching on the key POSITION (`"field":`) rather than the bare word also
        avoids latching onto the word appearing inside an earlier string value --
        e.g. an fp_explanation reading "...the result is not exploitable" would
        otherwise make the next "FP"-looking token the measurement.
      * The key may occur MORE THAN ONCE. A reasoning model's <think> trace discusses
        the JSON before emitting it, so `"result":` appears mid-deliberation first and
        in the final JSON last; measuring the first occurrence then scores a thinking
        token, not the decision (observed: confidence pinned to 0.33-0.80, no ranking
        power). config.LOGPROB_VERDICT_MATCH selects which occurrence to trust:
        "last" (default, reasoning-safe -- the emitted JSON is always last) or "first"
        (original behaviour). For a non-reasoning model the key appears once, so the
        two are identical and prior runs are unchanged. `attacker_source` rarely
        appears verbatim in prose, which is why source confidence was never affected.

    The probabilities are renormalised over just the allowed labels: raw
    exp(logprob) is diluted by quote/whitespace variants the grammar would never
    accept, which would understate confidence. Returns None when the value token
    cannot be located (caller treats that as "no signal").
    """
    if not token_entries or not values:
        return None

    labels = [v.upper() for v in values]
    toks = [(e.get("token") or "") for e in token_entries]

    # Reassemble the decoded text, remembering where each token starts.
    text, starts = "", []
    for tok in toks:
        starts.append(len(text))
        text += tok

    def label_of(tok: str):
        """Which allowed label this (possibly partial) token commits to, if any."""
        cleaned = tok.strip().strip('"').strip().upper()
        if not cleaned:
            return None
        matches = [lab for lab in labels if lab.startswith(cleaned) or cleaned.startswith(lab)]
        return matches[0] if len(matches) == 1 else None

    def dist_at(value_pos):
        """Full per-label distribution at the token covering `value_pos`.

        Returns {LABEL: prob} renormalised over the labels that appear (they sum to
        1.0), or None when the token is not a verdict / cannot be located. The
        caller reads the chosen label's entry as the scalar confidence and keeps the
        whole dict for confidence_tp / confidence_fp / confidence_na.
        """
        idx = None
        for i, start in enumerate(starts):
            if start <= value_pos < start + len(toks[i]):
                idx = i
                break
            if start > value_pos:          # value began exactly at a token boundary
                idx = i
                break
        if idx is None:
            return None
        chosen = label_of(toks[idx])
        if chosen is None:
            return None
        entry = token_entries[idx]
        probs = {}
        for alt in (entry.get("top_logprobs") or []):
            lab = label_of(alt.get("token") or "")
            if lab is None:
                continue
            probs[lab] = probs.get(lab, 0.0) + math.exp(alt["logprob"])
        probs.setdefault(chosen, math.exp(entry["logprob"]))
        total = sum(probs.values())
        if total <= 0:
            return None
        # A label absent from top_logprobs is NOT a label with zero mass -- it is a
        # label whose mass fell below the top-N measurement floor. Reporting it as
        # 0.0 turns a censored observation into a fake certainty: the winner then
        # renormalises to exactly 1.0. That is what a reasoning trace does to this
        # probe (the answer token is a foregone conclusion), so the flag matters.
        # The dict still reports 0.0 -- downstream code and every prior run expect
        # the full label set -- but the censoring is recorded alongside it so a
        # 1.0 can be read as ">= 1 - floor" rather than as a measured certainty.
        alts = [a.get("logprob") for a in (entry.get("top_logprobs") or [])
                if isinstance(a.get("logprob"), (int, float))]
        _set_diag(
            logprob_censored=any(lab not in probs for lab in labels),
            logprob_missing=[lab for lab in labels if lab not in probs],
            logprob_floor=(math.exp(min(alts)) if alts else None),
            logprob_raw_total=total,
            logprob_topn=len(alts),
        )
        dist = {lab.upper(): 0.0 for lab in labels}
        dist.update({lab: max(0.0, min(1.0, p / total)) for lab, p in probs.items()})
        return dist

    matches = list(re.finditer(r'"%s"\s*:\s*"?' % re.escape(field), text))
    if not matches:
        return None

    if str(getattr(config, "LOGPROB_VERDICT_MATCH", "last")).strip().lower() == "first":
        # Original behaviour: the first key occurrence, even if it is not a verdict.
        return dist_at(matches[0].end())
    # Reasoning-safe: the last occurrence that actually resolves to a verdict token
    # (the emitted JSON), skipping any mention inside the thinking trace.
    for m in reversed(matches):
        dist = dist_at(m.end())
        if dist is not None:
            return dist
    return None


def _openai_structured(system_prompt, user_message, schema, client) -> dict:
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})

    response = client.chat.completions.create(
        model=config.OPENAI_MODEL,
        messages=messages,
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "analysis_result", "schema": schema, "strict": False},
        },
        timeout=config.OPENAI_TIMEOUT,
    )
    return _parse_json(response.choices[0].message.content)


def _anthropic_structured(system_prompt, user_message, schema, client) -> dict:
    # Anthropic has no response_format; force a single tool call whose input
    # schema is our schema, then read the tool input as the structured result.
    response = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=4096,
        temperature=1,
        system=system_prompt or "",
        tools=[{
            "name": "record_analysis",
            "description": "Record the structured analysis result.",
            "input_schema": schema,
        }],
        tool_choice={"type": "tool", "name": "record_analysis"},
        messages=[{"role": "user", "content": [{"type": "text", "text": user_message}]}],
        timeout=config.ANTHROPIC_TIMEOUT,
    )
    for block in response.content:
        if getattr(block, "type", None) == "tool_use":
            return block.input
    raise LLMError("Anthropic returned no tool_use block")


def _gemini_structured(system_prompt, user_message, schema, client) -> dict:
    config_dict = {
        "temperature": 1.0,
        "response_mime_type": "application/json",
        "response_schema": schema,
    }
    if system_prompt:
        config_dict["system_instruction"] = {"parts": [{"text": system_prompt}]}

    contents = [{"role": "user", "parts": [{"text": user_message}]}]
    prompt_tokens = estimate_token_count(user_message + (system_prompt or ""))

    max_retries = 50
    for retry in range(max_retries):
        _token_bucket.wait_and_add(prompt_tokens)
        try:
            response = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=contents,
                config=config_dict,
            )
            return _parse_json(response.text)
        except Exception as e:
            error_str = str(e)
            is_rate_limit = (
                "429" in error_str or "rate_limit" in error_str.lower()
                or "quota" in error_str.lower() or "RESOURCE_EXHAUSTED" in error_str
            )
            if is_rate_limit:
                _token_bucket.remove(prompt_tokens)
            if is_rate_limit and retry < max_retries - 1:
                wait_time = min(120, 5 * (2 ** retry)) * random.uniform(0.9, 1.1)
                print(f"  ⚠️  Rate limit - waiting {wait_time:.0f}s - retry {retry+2}/{max_retries}...")
                time.sleep(wait_time)
                continue
            raise LLMError(f"Gemini query failed: {error_str[:300]}")
    raise LLMError("Gemini query exhausted retries")


def _parse_json(text: str) -> dict:
    """Parse a JSON object, tolerating stray prose or ```json fences."""
    if text is None:
        raise LLMError("Empty response")
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Fall back to the first {...} span.
    start = text.find('{')
    end = text.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    raise LLMError(f"Could not parse JSON from response: {text[:200]}")
