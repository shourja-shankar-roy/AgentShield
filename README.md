# AgentShield

### A Secure AI Agent Framework with Prompt Injection Detection, Role-Based Access Control, and Runtime Security Enforcement

AgentShield is a security-focused AI agent framework developed to protect tool-using AI agents against prompt injection attacks, unauthorized tool access, indirect prompt injection, and sensitive information disclosure.

The framework integrates security mechanisms into the AI agent execution workflow to inspect user inputs, validate tool requests, enforce access permissions, inspect document content, and filter sensitive information from AI-generated responses.

---

## 1. Project Overview

AI agents can interact with external tools, access organizational data, and perform operations based on user instructions. However, these capabilities introduce security risks such as:

- Prompt injection attacks
- Unauthorized tool execution
- Privilege escalation
- Indirect prompt injection through documents
- Sensitive information disclosure

AgentShield addresses these challenges through a runtime security layer that monitors and controls AI agent operations.

## 2. Key Features

| Feature | Description |
|---|---|
| Prompt Injection Detection | Identifies suspicious and potentially malicious user inputs. |
| Role-Based Access Control | Restricts access according to user roles and permissions. |
| Tool Authorization | Verifies whether a user is permitted to execute a requested tool. |
| Argument Validation | Validates tool arguments before execution. |
| Document Inspection | Detects suspicious instructions embedded in documents. |
| Document Quarantine | Isolates documents that exceed the configured risk threshold. |
| Output Inspection | Detects and sanitizes sensitive information in responses. |
| Audit Logging | Records security decisions and execution events using SQLite. |
| Attack Simulation | Tests security mechanisms against controlled attack scenarios. |

## 3. System Architecture

AgentShield consists of two major architectural components.

### 3.1 AI Agent Architecture

- Local Large Language Model integration
- Agent runtime
- Tool registry
- Tool execution
- Streamlit application interface
- Web search integration

### 3.2 Security Architecture

- Input inspection
- Identity management
- Role-Based Access Control (RBAC)
- Tool authorization
- Argument validation
- Document inspection
- Output inspection
- Security engine
- Audit logging

The security mechanisms operate alongside the AI agent to inspect and control sensitive operations during execution.

## 4. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application development |
| Streamlit | Web-based user interface |
| Ollama | Local LLM execution |
| Qwen 3.5 4B | Language model |
| SQLite | Audit logging and event storage |
| Requests | API communication |
| Pytest | Regression testing |
| Plotly | Data visualization |

## 5. Project Structure

```text
AgentShield/
│
├── agent/
│   ├── agent_runtime.py
│   ├── llm_client.py
│   ├── tool_registry.py
│   └── web_search.py
│
├── attacks/
│   └── attack_simulator.py
│
├── data/
│   ├── documents/
│   └── mock_records.json
│
├── database/
│   └── audit_logger.py
│
├── evaluation/
│   ├── benign_input_evaluation.py
│   ├── contextual_bypass_evaluation.py
│   ├── holdout_input_evaluation.py
│   ├── input_inspector_benchmark.py
│   └── run_full_evaluation.py
│
├── reports/
│
├── security/
│   ├── argument_validator.py
│   ├── identity.py
│   ├── input_inspector.py
│   ├── output_inspector.py
│   ├── rbac.py
│   ├── security_engine.py
│   └── tool_authorization.py
│
├── tests/
│   └── test_regression.py
│
├── tools/
│   ├── employee_tools.py
│   └── tool_executor.py
│
├── app.py
└── requirements.txt
```

## 6. Installation and Setup

### Prerequisites

- Python 3.10 or later
- Git
- Ollama
- Qwen 3.5 4B model

### Step 1: Clone the Repository

```bash
git clone https://github.com/shourja-shankar-roy/AgentShield.git
cd AgentShield
```

### Step 2: Create a Virtual Environment

```bash
python -m venv .venv
```

Activate the environment on Windows:

```powershell
.venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Set Up the Local Language Model

Install Ollama and download the model:

```bash
ollama pull qwen3.5:4b
```

Ensure that Ollama is running before starting the application.

### Step 5: Run the Application

```bash
streamlit run app.py
```

The AgentShield application will open in your browser.

## 7. Security Evaluation

The framework was evaluated using controlled attack simulations, regression tests, input inspection benchmarks, contextual prompt injection tests, and benign input evaluation.

| Evaluation | Result |
|---|---:|
| Regression Testing | 10/10 passed |
| Attack Simulation | 9/9 expected outcomes passed |
| Input Inspector Benchmark | 100/100 correct classifications |
| Contextual Bypass Evaluation | 5/5 malicious cases detected |
| Benign Input Evaluation | 10/10 accepted |

**Evaluation Note:** These results represent controlled project test datasets and scenarios. They should not be interpreted as proof of complete protection against all real-world attacks.

## 8. Limitations

- Input inspection primarily relies on predefined detection rules and patterns.
- Evaluation datasets are limited in size and scope.
- Local language model performance depends on available hardware resources.
- Identity management uses demonstration identities rather than production-grade authentication.
- The framework uses mock organizational data for testing and demonstration.

## 9. Future Scope

- Integration of advanced machine-learning-based prompt injection detection.
- Improved contextual and semantic security analysis.
- Stronger authentication and identity management.
- Expanded adversarial evaluation datasets.
- Integration with enterprise AI agents and additional tools.
- Advanced security monitoring and analytics.

## 10. Contributors

- **Shourja Shankar Roy**
- **Project Team Member 2**

## 11. Project Information

| Category | Details |
|---|---|
| Project Name | AgentShield |
| Domain | Artificial Intelligence and Cybersecurity |
| Institution | KIIT Deemed to be University |
| Degree | B.Tech in Computer Science and Engineering |

---

*AgentShield is an academic project developed for research and educational purposes. It is a prototype and is not intended to replace production-grade security controls.*
