"""
GridGuard — Arize Phoenix Observability Setup
MUST be imported before any agent execution.
Registers Phoenix as the OTel tracer provider and auto-instruments Gemini/VertexAI.
"""

import os
from dotenv import load_dotenv

load_dotenv()

tracer_provider = None


def _enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def initialize_phoenix():
    """
    Initialize Arize Phoenix tracing.
    Call this once at application startup before any agent runs.
    Returns the configured tracer instance.
    """
    from opentelemetry import trace

    if not _enabled("GRIDGUARD_ENABLE_PHOENIX_TRACING", default=True):
        print("[SKIP] Phoenix tracing disabled by configuration")
        return trace.get_tracer("gridguard_noop")

    phoenix_api_key = _get_phoenix_api_key()
    phoenix_base_url = os.getenv("PHOENIX_BASE_URL", "https://app.phoenix.arize.com")
    collector_endpoint = os.getenv("PHOENIX_COLLECTOR_ENDPOINT", phoenix_base_url)
    project_name = os.getenv("PHOENIX_PROJECT_NAME", "gridguard")
    if not phoenix_api_key:
        return trace.get_tracer("gridguard_noop")

    from phoenix.otel import register

    # Build the correct OTLP collector endpoint for Arize Phoenix cloud.
    # The register() function needs the full OTLP HTTP endpoint.
    otlp_endpoint = "https://app.phoenix.arize.com/v1/traces"

    # Register Phoenix as the OTel tracing backend
    global tracer_provider
    tracer_provider = register(
        project_name=project_name,
        api_key=phoenix_api_key,
        endpoint=otlp_endpoint,
        batch=True,
        verbose=False,
    )

    # Auto-instrument Vertex AI (ADK uses Vertex AI under the hood)
    try:
        from openinference.instrumentation.vertexai import VertexAIInstrumentor
        VertexAIInstrumentor().instrument(tracer_provider=tracer_provider)
        print("[OK] VertexAI auto-instrumentation enabled")
    except Exception as e:
        print(f"[SKIP] VertexAI instrumentation: {e}")

    # Auto-instrument direct Gemini API calls
    try:
        from openinference.instrumentation.google_genai import GoogleGenAIInstrumentor
        GoogleGenAIInstrumentor().instrument(tracer_provider=tracer_provider)
        print("[OK] GoogleGenAI auto-instrumentation enabled")
    except Exception as e:
        print(f"[SKIP] GoogleGenAI instrumentation: {e}")

    tracer = trace.get_tracer("gridguard")
    print(f"[OK] Phoenix tracing initialized -> {collector_endpoint} (project: {project_name})")
    return tracer


def flush_traces(timeout_millis: int = 10000) -> bool:
    """Flush completed spans before evaluation annotations are submitted."""
    if tracer_provider is None:
        return False
    try:
        return bool(tracer_provider.force_flush(timeout_millis=timeout_millis))
    except Exception:
        return False


def _get_phoenix_api_key() -> str:
    """Get Phoenix API key — tries Secret Manager first, falls back to env var."""
    # Try GCP Secret Manager in production
    if os.getenv("GRIDGUARD_ENV", "development") != "development":
        try:
            from tools.secrets import get_secret
            return get_secret("PHOENIX_API_KEY")
        except Exception:
            pass

    # Fall back to environment variable (local dev)
    key = os.getenv("PHOENIX_API_KEY", "")
    if not key:
        print("[WARN] PHOENIX_API_KEY not set - traces will not be sent to Phoenix")
    return key


# Initialize on import — module-level tracer for use across all tools
try:
    tracer = initialize_phoenix()
except Exception as e:
    # Graceful degradation — app runs without observability if Phoenix is unavailable
    print(f"[WARN] Phoenix initialization failed: {e} - running without tracing")
    from opentelemetry import trace
    tracer = trace.get_tracer("gridguard_noop")
