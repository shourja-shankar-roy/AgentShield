
import json
import requests

from agent.tool_registry import get_tool_definitions


# ==================================================
# OLLAMA CONFIGURATION
# ==================================================

OLLAMA_URL = "http://localhost:11434/api/chat"

MODEL = "qwen3.5:4b"

MAX_RESPONSE_TOKENS = 2048

CONTEXT_LENGTH = 8192

REQUEST_TIMEOUT = (10, 600)


# ==================================================
# SHARED REQUEST SETTINGS
# ==================================================

def get_model_options():
    return {
        "num_predict": MAX_RESPONSE_TOKENS,
        "temperature": 0.3,
        "num_ctx": CONTEXT_LENGTH
    }


# ==================================================
# STREAMING MODEL RESPONSE
# ==================================================

def stream_model(messages):
    """
    Generate a normal streaming response using Ollama.

    Preserves the existing chatbot functionality.
    """

    payload = {
        "model": MODEL,
        "messages": messages,
        "think": False,
        "stream": True,
        "keep_alive": "30m",
        "options": get_model_options()
    }

    completed = False

    try:
        with requests.post(
            OLLAMA_URL,
            json=payload,
            stream=True,
            timeout=REQUEST_TIMEOUT
        ) as response:

            response.raise_for_status()

            for line in response.iter_lines():

                if not line:
                    continue

                data = json.loads(line.decode("utf-8"))

                if "error" in data:
                    raise RuntimeError(data["error"])

                message = data.get("message", {})
                content = message.get("content", "")

                if content:
                    yield content

                if data.get("done", False):
                    completed = True

                    if data.get("done_reason") == "length":
                        raise RuntimeError(
                            "The response reached its token limit "
                            "and may be incomplete. Try a shorter "
                            "request or increase MAX_RESPONSE_TOKENS."
                        )

                    break

        if not completed:
            raise RuntimeError(
                "Ollama's response stream ended unexpectedly."
            )

    except requests.exceptions.Timeout as error:
        raise RuntimeError(
            "The model response timed out. Try a shorter question."
        ) from error

    except requests.exceptions.ConnectionError as error:
        raise RuntimeError(
            "Could not connect to Ollama. "
            "Check whether the Ollama service is running."
        ) from error

    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"Ollama request failed: {error}"
        ) from error

    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError(
            f"Invalid data received from Ollama: {error}"
        ) from error


# ==================================================
# NON-STREAMING MODEL RESPONSE
# ==================================================

def chat_with_tools(messages, tools=None):
    """
    Request a model response with native tool-calling support.

    IMPORTANT:
    This function only receives proposed tool calls.
    It NEVER executes tools.

    All proposed calls must be passed to the
    AgentShield security engine separately.
    """

    if not isinstance(messages, list) or not messages:
        raise ValueError("Messages must be a non-empty list.")

    if tools is None:
        tools = get_tool_definitions()

    if not isinstance(tools, list):
        raise ValueError("Tool definitions must be a list.")

    payload = {
        "model": MODEL,
        "messages": messages,
        "tools": tools,
        "think": False,
        "stream": False,
        "keep_alive": "30m",
        "options": get_model_options()
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        if "error" in data:
            raise RuntimeError(data["error"])

        message = data.get("message")

        if not isinstance(message, dict):
            raise RuntimeError(
                "Ollama returned an invalid message response."
            )

        return message

    except requests.exceptions.Timeout as error:
        raise RuntimeError(
            "The model response timed out during tool calling."
        ) from error

    except requests.exceptions.ConnectionError as error:
        raise RuntimeError(
            "Could not connect to Ollama. "
            "Check whether the Ollama service is running."
        ) from error

    except requests.exceptions.RequestException as error:
        raise RuntimeError(
            f"Ollama tool-calling request failed: {error}"
        ) from error

    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(
            f"Invalid response received from Ollama: {error}"
        ) from error


# ==================================================
# NON-STREAMING COMPATIBILITY FUNCTION
# ==================================================

def ask_model(prompt=None, messages=None):

    if messages is None:

        if prompt is None:
            raise ValueError(
                "Provide either prompt or messages."
            )

        messages = [
            {
                "role": "user",
                "content": prompt
            }
        ]

    return "".join(stream_model(messages))


# ==================================================
# DIRECT TEST
# ==================================================

if __name__ == "__main__":

    test_messages = [
        {
            "role": "user",
            "content": (
                "Find the employee record for EMP001. "
                "Use the get_employee_record tool."
            )
        }
    ]

    print("\nAgentShield Tool-Calling Test\n")
    print("Model:", MODEL)
    print("Thinking: Disabled")
    print("Maximum response tokens:", MAX_RESPONSE_TOKENS)
    print("Context length:", CONTEXT_LENGTH)

    try:

        message = chat_with_tools(test_messages)

        print("\nModel response:")
        print(json.dumps(message, indent=4))

        tool_calls = message.get("tool_calls", [])

        if tool_calls:
            print("\nProposed tool calls:")

            for tool_call in tool_calls:
                function = tool_call.get("function", {})

                print(
                    "Tool:",
                    function.get("name")
                )

                print(
                    "Arguments:",
                    json.dumps(
                        function.get("arguments", {}),
                        indent=4
                    )
                )

            print(
                "\nTool calls received successfully. "
                "No tools were executed."
            )

        else:
            print("\nThe model returned no tool calls.")

    except Exception as error:
        print("\nGeneration error:", error)
