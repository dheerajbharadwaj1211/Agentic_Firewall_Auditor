"""Gemini SDK adapter. Automatic function execution is explicitly disabled."""
import os
import re
from .agent import AgentError, ProviderFailure, ToolCall, Turn


class GeminiProvider:
    mode = "live_gemini_live_vm"

    def __init__(self, model=None, client=None, api_version=None):
        self.model = model or os.environ.get("GEMINI_MODEL")
        if not self.model or not re.fullmatch(r"(?:models/)?[A-Za-z0-9][A-Za-z0-9._-]{0,119}", self.model):
            raise AgentError("Set GEMINI_MODEL to a function-calling model available in your Gemini account")
        self.api_version = api_version or os.environ.get("GEMINI_API_VERSION", "v1beta")
        if self.api_version not in {"v1", "v1beta"}:
            raise AgentError("GEMINI_API_VERSION must be v1 or v1beta")
        from google.genai import types
        self.types = types
        self._owns_client = client is None
        if client is None:
            key = os.environ.get("GEMINI_API_KEY")
            if not key:
                raise AgentError("Set GEMINI_API_KEY locally; never put it in source or chat")
            from google import genai
            # Explicit key prevents a different GOOGLE_API_KEY silently taking precedence.
            client = genai.Client(vertexai=False, api_key=key, http_options=types.HttpOptions(
                api_version=self.api_version, timeout=30000, retry_options=types.HttpRetryOptions(attempts=1)))
        self.client = client
        self.contents = []
        self._pending = {}

    def close(self):
        if self._owns_client:
            self.client.close()

    def start(self, instructions, goal, tools):
        t = self.types
        self.instructions = instructions
        self.tools = [t.Tool(function_declarations=[t.FunctionDeclaration(**s) for s in tools])]
        self.contents = [t.Content(role="user", parts=[t.Part.from_text(text=goal)])]
        self._pending = {}
        self._turn = 0

    def next(self, results, timeout, max_output_tokens):
        t = self.types
        if results:
            parts = []
            for result in results:
                original_id = self._pending.get(result["id"])
                kwargs = {"name": result["name"], "response": result["result"]}
                if original_id:
                    kwargs["id"] = original_id
                parts.append(t.Part(function_response=t.FunctionResponse(**kwargs)))
            self.contents.append(t.Content(role="tool", parts=parts))
        config = t.GenerateContentConfig(
            system_instruction=self.instructions, tools=self.tools,
            automatic_function_calling=t.AutomaticFunctionCallingConfig(disable=True),
            tool_config=t.ToolConfig(function_calling_config=t.FunctionCallingConfig(mode="ANY")),
            max_output_tokens=max_output_tokens,
            http_options=t.HttpOptions(timeout=max(1, int(timeout * 1000))))
        from google.genai.errors import APIError
        try:
            response = self.client.models.generate_content(model=self.model, contents=self.contents, config=config)
        except APIError as exc:
            raise ProviderFailure(getattr(exc, "code", None)) from None
        self._turn += 1
        if not response.candidates or response.candidates[0].content is None:
            raise AgentError("Gemini returned no usable candidate")
        content = response.candidates[0].content
        # Preserve complete content, including thought signatures, only in memory.
        # Neither text reasoning nor signatures enter saved audit reports.
        self.contents.append(content)
        calls = []
        self._pending = {}
        for index, part in enumerate(content.parts or []):
            if part.function_call is not None:
                fc = part.function_call
                call_id = f"gemini-{self._turn}-{index}"
                self._pending[call_id] = fc.id
                calls.append(ToolCall(call_id, fc.name, fc.args))
        usage = response.usage_metadata
        count = ((usage.candidates_token_count or 0) + (usage.thoughts_token_count or 0)) if usage else 0
        return Turn(calls, count)
