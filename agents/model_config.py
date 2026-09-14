"""Shared Gemini configuration for GridGuard agents."""

from __future__ import annotations

import os

from google.adk.models.google_llm import Gemini
from google.genai import types, Client


# Models to try in order if the primary is unavailable.
# Update this list when Google deprecates a generation.
_FALLBACK_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-3.5-flash",
]


def build_gridguard_model() -> Gemini:
    """
    Create a Gemini client with retries.

    When GOOGLE_GENAI_USE_VERTEXAI=false, uses Google AI Studio (free tier)
    via GOOGLE_API_KEY — no GCP billing required.
    When GOOGLE_GENAI_USE_VERTEXAI=true, uses Vertex AI (requires GCP billing).

    Raises a clear ValueError if the model is deprecated (404) or quota is
    exhausted (429) so the pipeline surfaces a useful message instead of the
    raw ADK wrapper text.
    """
    use_vertexai = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "false").lower() in ("true", "1", "yes")

    retry = types.HttpRetryOptions(
        attempts=6,
        initial_delay=2.0,
        max_delay=30.0,
        exp_base=2.0,
        jitter=0.5,
        # Retry on quota (429) and transient server errors only.
        # Do NOT retry 404 — model is gone, retrying won't help.
        http_status_codes=[429, 500, 502, 503, 504],
    )

    if use_vertexai:
        client = Client(
            vertexai=True,
            project=os.getenv("GOOGLE_CLOUD_PROJECT"),
            location=os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"),
        )
    else:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(
                "GOOGLE_API_KEY is not set. "
                "Get a free key at https://aistudio.google.com/apikey and add it to .env"
            )
        client = Client(api_key=api_key)

    model_name = os.getenv("GRIDGUARD_MODEL", "gemini-3.5-flash-lite")

    # Warn if the configured model is not in our known-good list
    if model_name not in _FALLBACK_MODELS:
        print(
            f"[WARN] GRIDGUARD_MODEL={model_name!r} is not in the known-good model list. "
            f"If you get a 404, update GRIDGUARD_MODEL in .env to one of: {_FALLBACK_MODELS}"
        )

    return Gemini(
        model=model_name,
        client=client,
        retry_options=retry,
    )


def get_model_error_hint(error_str: str) -> str:
    """
    Return a human-readable hint for common Gemini API errors.
    Used by pipeline_runner to surface clear messages in the dashboard.
    """
    e = error_str.lower()
    model_name = os.getenv("GRIDGUARD_MODEL", "gemini-3.5-flash-lite")
    fallbacks = [m for m in _FALLBACK_MODELS if m != model_name]

    if "404" in e or "no longer available" in e or "not found" in e:
        return (
            f"Model '{model_name}' has been deprecated by Google. "
            f"Update GRIDGUARD_MODEL in .env to one of: {fallbacks}. "
            f"Then restart the app."
        )
    if "429" in e or "resource_exhausted" in e or "quota" in e:
        return (
            f"Free tier quota exhausted for '{model_name}'. "
            f"Options: (1) wait until midnight for quota reset, "
            f"(2) switch GRIDGUARD_MODEL in .env to a model with higher quota: {fallbacks}."
        )
    if "400" in e and "invalid_argument" in e:
        return (
            "Invalid request sent to Gemini API (400). "
            "This is usually a tool schema issue. Check the logs for 'additionalProperties'."
        )
    if "403" in e or "permission_denied" in e:
        return (
            "Permission denied (403). "
            "If using Vertex AI, ensure billing is enabled and the Vertex AI API is active. "
            "If using AI Studio, check that GOOGLE_API_KEY is valid."
        )
    return error_str
