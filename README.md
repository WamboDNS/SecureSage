# SecureSage

**SecureSage** is an automated code review agent focused on Python security. It combines static analysis (Bandit), structural inspection (AST), and LLM-based reasoning to identify vulnerabilities and explain how to fix them.

This project is built entirely in a Jupyter notebook and serves as a demonstration of a self-contained reasoning agent that uses tools effectively.

## What it does

- ReAct-style loop with real tool execution (Bandit, AST parsing, LLM fix generation)
- Anayzes Python code for security issues. More specifically, it:
  - Scans for known vulnerabilities in dependencies
  - Identifies insecure coding patterns
  - Suggests fixes and improvements
- Runs inside a notebook with full visibility of every step
- Tool output and agent thoughts are printed for inspection
- Generates clean Markdown reports summarizing security findings

## Usage

1. Clone the repo and set up your environment:

```bash
git clone https://github.com/wambodns/securesage.git
cd securesage
uv venv
uv sync
```

2. Export your OpenAI key in a .env:
```
OPENAI_API_KEY="YOUR_KEY"
```

3. Using the notebook:
You have to enter the path to the Python file you want to analyze in the `CODE_PATH` variable at the start of the notebook. The report will be stored unter `reports`.
You have the option to either let the agent scan recursively though a directory or just analyze a single file. If you choose the directory, the agent will generate a summary and a rather short report for each file.
If instead, you choose a single file, the report will go more into detail and be more thorough.

Have fun with the agent!

---
Thanks to [Will Brown](https://x.com/willccbb) for the inspiration and some parts of the code structure.