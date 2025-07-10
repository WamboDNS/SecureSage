# SecureSage: Automated Python Security Analysis Agent

**SecureSage** is an automated code review agent designed to enhance the security of Python projects. It integrates static analysis, Abstract Syntax Tree inspection, Large Language Model based reasoning, and dependency vulnerability checking to identify potential security issues and provide actionable recommendations.

This project is implemented as a self-contained Jupyter/Marimo Notebook, demonstrating an agent capable of tool use and iterative reasoning for security tasks.
Thanks to marimo's format, you can run the notebook as well as the app.

## Core Capabilities

- **Comprehensive Security Analysis**: Identifies vulnerabilities in Python code, including insecure deserialization, command injection, hardcoded secrets, and OWASP Top 10 issues
- **Dependency Scanning**: Checks for known vulnerabilities in project dependencies using pip-audit
- **Configuration Review**: Analyzes configuration files for security misconfigurations and exposed secrets
- **Smart Documentation**: Generates detailed security reports in both Markdown and HTML formats with modern styling
- **AI-Powered Analysis**: Uses GPT-4.1 for intelligent code review and vulnerability assessment
- **External Knowledge Integration**: Leverages Brave Search API to validate findings against current security best practices

## Agent Operation Overview

SecureSage functions based on the ReAct (Reasoning and Acting) paradigm:
1.  **Reasoning:** The LLM (I suggest GPT-4.1) analyzes the current state and determines the next logical step or tool to use.
2.  **Acting:** The agent executes the chosen tool (e.g., `suggest_fix`, `static_analysis`, `check_dependencies`).
3.  **Observation:** The output from the tool is returned to the LLM.
4.  The LLM processes this new information, repeating the cycle or concluding with a final security report if sufficient information has been gathered. This iterative approach allows for adaptive analysis based on discovered findings.

## Preview (old, sequential)

https://github.com/user-attachments/assets/06bd1906-200e-4a01-8f68-08135553898c


## Requirements

* Python >= 3.13
* OpenAI API key (required)
* Brave Search API key (optional, for enhanced documentation search)

## Usage Instructions

1.  **Environment Setup:**
    ```bash
    git clone https://github.com/wambodns/securesage.git
    cd securesage
    
    # Option 1: Using uv
    uv venv
    uv sync
    
    # Option 2: Using pip
    python -m venv .venv
    source .venv/bin/activate
    pip install -e .
    ```

2.  **API Key Configuration:**
    Create a `.env` file in the root `securesage` directory and add your API keys:
    ```
    OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
    BRAVE_API_KEY="YOUR_BRAVE_SEARCH_API_KEY" # Optional: For enhanced documentation search
    ```
    The `BRAVE_API_KEY` is optional and enables the `doc_search_with_brave` tool for external documentation retrieval. This tool helps validate security patterns and provides up-to-date security best practices.

3.  **Running the Analysis:**
    *   Open the `SecureSage.py` Marimo Notebook.
    *   The application will prompt you to enter the path to analyze, or you can provide it as a command-line argument.
    *   You can analyze either:
        *   **Single File Analysis:**
            ```python
            /path/to/your/python_file.py
            ```
            This mode provides a detailed and thorough report for the specified file.
        *   **Directory Analysis:**
            ```python
            /path/to/your/project_directory/
            ```
            This mode recursively scans the directory, generating a summary report for the entire project and individual, concise reports for each relevant file.
    *   Execute the notebook cells sequentially.
    *   Security reports will be saved in Markdown format in the `reports/` directory.

4.  **Running as a Standalone Application:**
    You can run SecureSage directly from the terminal in two ways:

    ```bash
    # Method 1: Provide the path as a command-line argument
    uv run SecureSage.py /path/to/analyze

    # Method 2: Run without arguments and enter the path when prompted
    uv run SecureSage.py
    # You will be prompted to enter the path to analyze
    ```

    The application will launch the Marimo interface in your default web browser, where you can interact with the security analysis tools.

## Report Generation

SecureSage generates detailed security reports in both Markdown and HTML formats. The reports are saved in the `reports/` directory with the following features:

* **Report Format**: Each report includes:
  * A summary of the file/project purpose
  * Detected vulnerabilities with severity levels
  * Detailed explanations of each issue
  * Suggested fixes with example code
  * References to relevant security standards (CWE, OWASP, etc.)

* **Output Formats**:
  * Markdown (`.md`) for easy reading and version control
  * HTML (`.html`) for formatted viewing in browsers

## Project Structure

```
securesage/
├── SecureSage.py          # Main Marimo notebook / app
├── example_code/          # Example code for testing
├── reports/              # Generated security reports
├── pyproject.toml        # Project dependencies
└── README.md            # This file
```

---
Thanks to [Will Brown](https://x.com/willccbb) for the inspiration and some parts of the code structure.
