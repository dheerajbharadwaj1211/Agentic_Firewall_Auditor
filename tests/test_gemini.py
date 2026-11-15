"""SDK contract tests using real SDK types and a mocked network client."""
import os
import json
import unittest
from unittest.mock import Mock, patch
from google.genai import types
from firewall_auditor.agent import AgentError, ProviderFailure, tool_schemas
from firewall_auditor.gemini import GeminiProvider


class GeminiContractTests(unittest.TestCase):
    def response(self, name="get_routes", args=None, signature=b"opaque-signature"):
        return types.GenerateContentResponse(candidates=[types.Candidate(content=types.Content(
            role="model", parts=[types.Part(function_call=types.FunctionCall(name=name,args=args or {"host":"vm"},id="server-call"),
                                            thought_signature=signature)]))],
            usage_metadata=types.GenerateContentResponseUsageMetadata(candidates_token_count=10,thoughts_token_count=5))

    def test_manual_calls_preserve_content_and_server_ids(self):
        client=Mock();client.models.generate_content.return_value=self.response()
        provider=GeminiProvider(model="test-model",client=client)
        provider.start("policy","goal",tool_schemas("vm"))
        turn=provider.next([],5,100)
        self.assertEqual(turn.output_tokens,15)
        self.assertEqual(turn.calls[0].arguments,{"host":"vm"})
        config=client.models.generate_content.call_args.kwargs["config"]
        self.assertTrue(config.automatic_function_calling.disable)
        self.assertEqual(config.http_options.timeout,5000)
        self.assertEqual(config.max_output_tokens,100)
        self.assertEqual(config.tool_config.function_calling_config.mode,"ANY")
        self.assertEqual(len(config.tools[0].function_declarations),10)
        provider.next([{"id":turn.calls[0].id,"name":"get_routes","result":{"untrusted_observation":True,"data":[]}}],5,100)
        contents=client.models.generate_content.call_args.kwargs["contents"]
        self.assertEqual(contents[1].parts[0].thought_signature,b"opaque-signature")
        self.assertEqual(contents[2].parts[0].function_response.id,"server-call")
        self.assertEqual(contents[2].parts[0].function_response.name,"get_routes")

    def test_quota_errors_have_safe_diagnostics_without_response_text(self):
        from google.genai.errors import ClientError
        client=Mock();client.models.generate_content.side_effect=ClientError(429,{"error":{"code":429,"message":"secret-url-with-key"}})
        provider=GeminiProvider("test-model",client=client);provider.start("policy","goal",tool_schemas("vm"))
        with self.assertRaises(ProviderFailure) as caught: provider.next([],5,100)
        self.assertEqual(caught.exception.status_code,429)
        self.assertNotIn("secret-url",str(caught.exception))

    def test_unadvertised_model_call_is_only_a_request(self):
        client=Mock();client.models.generate_content.return_value=self.response("execute_shell_command",{"host":"vm","command":"bad"})
        provider=GeminiProvider(model="test-model",client=client);provider.start("policy","goal",tool_schemas("vm"))
        turn=provider.next([],5,100)
        self.assertEqual(turn.calls[0].name,"execute_shell_command")
        # No callable is passed to the SDK; only declarations, so execution awaits policy validation.
        declarations=client.models.generate_content.call_args.kwargs["config"].tools[0].function_declarations
        self.assertNotIn("execute_shell_command",[d.name for d in declarations])

    def test_no_candidate_and_missing_config_fail_explicitly(self):
        client=Mock();client.models.generate_content.return_value=types.GenerateContentResponse()
        provider=GeminiProvider(model="test-model",client=client);provider.start("policy","goal",tool_schemas("vm"))
        with self.assertRaises(AgentError):provider.next([],5,100)
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(AgentError):GeminiProvider()
            with self.assertRaises(AgentError):GeminiProvider("test-model")

    def test_sdk_client_uses_explicit_environment_key_and_no_retries(self):
        with patch.dict(os.environ,{"GEMINI_API_KEY":"synthetic-key","GOOGLE_API_KEY":"other-key"}),patch("google.genai.Client") as client:
            provider=GeminiProvider("test-model")
            self.assertEqual(client.call_args.kwargs["api_key"],"synthetic-key")
            self.assertEqual(client.call_args.kwargs["http_options"].retry_options.attempts,1)
            self.assertEqual(client.call_args.kwargs["http_options"].api_version,"v1beta")
            provider.close();client.return_value.close.assert_called_once()


class GeminiSerializationTests(unittest.TestCase):
    def test_real_sdk_request_conversion_without_network(self):
        from google import genai
        body={"candidates":[{"content":{"role":"model","parts":[{"functionCall":{
            "name":"get_routes","args":{"host":"vm"}}}]},"finishReason":"STOP"}],
              "usageMetadata":{"candidatesTokenCount":7}}
        with genai.Client(vertexai=False,api_key="synthetic-not-a-real-key") as client:
            with patch.object(client._api_client,"request",return_value=Mock(body=json.dumps(body),headers={})) as request:
                provider=GeminiProvider("test-model",client=client)
                provider.start("read-only policy","audit vm",tool_schemas("vm"))
                turn=provider.next([],5,100)
                self.assertEqual(turn.calls[0].name,"get_routes")
                request_json=request.call_args.args[2]
                self.assertEqual(request_json['toolConfig']['functionCallingConfig']['mode'],'ANY')
                declarations=request_json['tools'][0]['functionDeclarations']
                self.assertEqual(declarations[0]['parameters_json_schema']['additionalProperties'],False)
                self.assertEqual(len(declarations),10)
                self.assertNotIn('automaticFunctionCalling',request_json)


class GeminiVersionTests(unittest.TestCase):
    def test_explicit_version_can_be_selected_and_invalid_version_rejected(self):
        with patch.dict(os.environ,{"GEMINI_API_KEY":"synthetic"}),patch("google.genai.Client") as client:
            provider=GeminiProvider("test-model",api_version="v1")
            self.assertEqual(client.call_args.kwargs["http_options"].api_version,"v1")
            provider.close()
            with self.assertRaises(AgentError):GeminiProvider("test-model",api_version="bad-version")

    def test_prefixed_and_short_model_ids_produce_same_sdk_request_path(self):
        from google import genai
        paths=[]
        for name in ("gemini-2.5-flash-lite","models/gemini-2.5-flash-lite"):
            with genai.Client(vertexai=False,api_key="synthetic",http_options=types.HttpOptions(api_version="v1beta")) as client:
                with patch.object(client._api_client,"request",return_value=Mock(body='{"candidates":[{"content":{"role":"model","parts":[]}}]}',headers={})) as request:
                    provider=GeminiProvider(name,client=client)
                    provider.start("policy","goal",tool_schemas("vm"));provider.next([],5,100)
                    paths.append(request.call_args.args[1])
        self.assertEqual(paths[0],paths[1])
        self.assertEqual(paths[0],"models/gemini-2.5-flash-lite:generateContent")
