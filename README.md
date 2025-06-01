# SecureSage: Automated Python Security Analysis Agent

**SecureSage** is an automated code review agent designed to enhance the security of Python projects. It integrates static analysis (`bandit`), Abstract Syntax Tree (AST) inspection, Large Language Model (LLM) based reasoning, and dependency vulnerability checking (`pip-audit`) to identify potential security issues and provide actionable recommendations.

This project is implemented as a self-contained Jupyter Notebook, demonstrating an agent capable of tool use and iterative reasoning for security tasks.

## Core Capabilities

*   **ReAct-Style Agent Loop:** Employs a reasoning and acting cycle where the agent makes decisions, executes tools, and processes results iteratively.
*   **Comprehensive Python Security Analysis:**
    *   **Dependency Scanning:** Checks project dependencies (e.g., `requirements.txt`, lock files) for known vulnerabilities using `pip-audit`.
    *   **Insecure Code Pattern Detection:** Identifies common insecure coding practices in Python code, including those listed in the OWASP Top 10 (e.g., command injection, insecure deserialization, hardcoded secrets).
    *   **Vulnerability Remediation Guidance:** Suggests specific code modifications to address identified vulnerabilities and explains the underlying security principles.
    *   **Contextual Analysis:** Capable of analyzing individual Python files or recursively scanning entire project directories to understand inter-file dependencies and data flow.
*   **Transparent Execution:** All agent operations, including internal "thoughts," tool calls, and tool outputs, are visible within the Jupyter Notebook environment, facilitating understanding and debugging.
*   **Structured Reporting:** Generates clear Markdown reports detailing security findings, their severity, and suggested fixes.

## Usage Instructions

1.  **Environment Setup:**
    ```bash
    git clone https://github.com/wambodns/securesage.git
    cd securesage
    uv venv      # Create a virtual environment using uv
    uv sync       # Install project dependencies
    source .venv/bin/activate # Activate the virtual environment
    ```

2.  **API Key Configuration:**
    Create a `.env` file in the root `securesage` directory and add your OpenAI API key:
    ```
    OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
    BRAVE_API_KEY="YOUR_BRAVE_SEARCH_API_KEY" # Optional: For the doc_search_with_brave tool
    ```
    The `BRAVE_API_KEY` is optional and enables the `doc_search_with_brave` tool for external documentation retrieval.

3.  **Running the Analysis:**
    *   Open the `securesage.ipynb` Jupyter Notebook.
    *   Locate the `CODE_PATH` variable in the first code cell.
    *   Set `CODE_PATH` to the target for analysis:
        *   **Single File Analysis:**
            ```python
            CODE_PATH = "./path/to/your/python_file.py"
            ```
            This mode provides a detailed and thorough report for the specified file.
        *   **Directory Analysis:**
            ```python
            CODE_PATH = "./path/to/your/project_directory/"
            ```
            This mode recursively scans the directory, generating a summary report for the entire project and individual, concise reports for each relevant file.
    *   Execute the notebook cells sequentially.
    *   Security reports will be saved in Markdown format in the `reports/` directory.

## Agent Operation Overview

SecureSage functions based on the ReAct (Reasoning and Acting) paradigm:
1.  **Reasoning:** The LLM analyzes the current state and determines the next logical step or tool to use.
2.  **Acting:** The agent executes the chosen tool (e.g., `suggest_fix`, `static_analysis`, `check_dependencies`).
3.  **Observation:** The output from the tool is returned to the LLM.
4.  The LLM processes this new information, repeating the cycle or concluding with a final security report if sufficient information has been gathered. This iterative approach allows for adaptive analysis based on discovered findings.

---
Thanks to [Will Brown](https://x.com/willccbb) for the inspiration and some parts of the code structure.