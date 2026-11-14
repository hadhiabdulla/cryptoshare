"""IBM watsonx.ai foundation-model call (free Lite plan, token allowance).

Needs WATSONX_API_KEY and WATSONX_SPACE_ID (deployment space associated with
the WML instance; this account's project is not). WATSONX_REGION defaults to
us-south where the instance lives. Uses only urllib - no SDK dep.
"""
import json
import os
import urllib.request

REGION = os.environ.get("WATSONX_REGION", "us-south")
MODEL = os.environ.get("WATSONX_MODEL", "ibm/granite-4-h-small")


def _iam_token(api_key: str) -> str:
    req = urllib.request.Request(
        "https://iam.cloud.ibm.com/identity/token",
        data=f"grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey={api_key}".encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return json.loads(urllib.request.urlopen(req).read())["access_token"]


def ask(prompt: str) -> str:
    api_key = os.environ["WATSONX_API_KEY"]
    space_id = os.environ["WATSONX_SPACE_ID"]
    token = _iam_token(api_key)
    # granite-4 instruct models expect the chat template; raw continuation
    # makes the model ramble past the answer and echo stray markup.
    chat = ("<|start_of_role|>user<|end_of_role|>" + prompt +
            "<|end_of_text|>\n<|start_of_role|>assistant<|end_of_role|>")
    payload = {
        "model_id": MODEL,
        "space_id": space_id,
        "input": chat,
        "parameters": {"max_new_tokens": 160, "temperature": 0.2,
                       "stop_sequences": ["<|end_of_text|>"]},
    }
    req = urllib.request.Request(
        f"https://{REGION}.ml.cloud.ibm.com/ml/v1/text/generation?version=2024-05-01",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    out = json.loads(urllib.request.urlopen(req).read())
    return out["results"][0]["generated_text"].strip()
