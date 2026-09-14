"""Runtime environment normalization shared by local and cloud entry points."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def configure_environment() -> None:
    """Load ``.env`` and normalize current Google ADK environment names."""
    load_dotenv()
    region = os.getenv("GOOGLE_CLOUD_LOCATION") or os.getenv("GOOGLE_CLOUD_REGION")
    if region:
        os.environ.setdefault("GOOGLE_CLOUD_LOCATION", region)
        os.environ.setdefault("GOOGLE_CLOUD_REGION", region)
    if os.getenv("GOOGLE_CLOUD_PROJECT"):
        os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "true")
        # Remove GOOGLE_GENAI_USE_ENTERPRISE — it conflicts with GOOGLE_GENAI_USE_VERTEXAI
        # and causes a UserWarning. GOOGLE_GENAI_USE_VERTEXAI is the correct variable.
        os.environ.pop("GOOGLE_GENAI_USE_ENTERPRISE", None)

    # ADC is preferred for local development. A stale key path would otherwise
    # prevent google-auth from falling back to `gcloud auth application-default`.
    credentials = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if credentials and not Path(credentials).expanduser().is_file():
        os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)

    # ADK 2.9+ enables JSON_SCHEMA_FOR_FUNC_DECL by default which generates
    # additionalProperties/title fields that Gemini API rejects with 400.
    # Disable it so ADK uses the standard function declaration schema.
    try:
        from google.adk.features import FeatureName, override_feature_enabled
        override_feature_enabled(FeatureName.JSON_SCHEMA_FOR_FUNC_DECL, False)
    except Exception:
        pass  # Older ADK versions don't have this feature flag — safe to ignore
