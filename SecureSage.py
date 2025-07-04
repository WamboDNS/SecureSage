import marimo

__generated_with = "0.13.15"
app = marimo.App(width="medium", app_title="SecureSage")


@app.cell
def _(os):
    import sys
    def get_code_path():
        # Check if path is provided as command line argument
        if len(sys.argv) > 1:
            return sys.argv[1]

        # If no argument provided, prompt the user
        while True:
            path = input("Enter the path to analyze (file or directory): ").strip()
            if os.path.exists(path):
                return path
            print(f"Error: Path '{path}' does not exist. Please try again.")

    CODE_PATH = get_code_path()
    return CODE_PATH, sys


@app.cell
def _():
    import dotenv
    import os
    import re
    import json
    from typing import Optional, Dict, Any, Union, List, Tuple
    from openai import OpenAI
    import tempfile
    import subprocess
    import json
    import ast
    import requests
    import markdown
    import asyncio
    import aiohttp
    import concurrent.futures
    dotenv.load_dotenv()

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    BRAVE_API_KEY = os.getenv("BRAVE_API_KEY", "")
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY environment variable is not set.")
    return (
        Any,
        BRAVE_API_KEY,
        Dict,
        List,
        OPENAI_API_KEY,
        OpenAI,
        Optional,
        Tuple,
        Union,
        aiohttp,
        ast,
        asyncio,
        concurrent,
        json,
        markdown,
        os,
        re,
        requests,
        subprocess,
        tempfile,
    )


@app.cell
def _(OPENAI_API_KEY, OpenAI):
    from openai import AsyncOpenAI
    model = "gpt-4.1"
    base_URL = "https://api.openai.com/v1"
    client = AsyncOpenAI(api_key=OPENAI_API_KEY, base_url=base_URL)
    return AsyncOpenAI, client, model


@app.cell
def _():
    system_prompt = """
    You are SecureSage — a vigilant, intelligent, and explainable security analyst. Your task is to review project files, understand what the code and configurations are doing, and identify potential security vulnerabilities. This includes issues in Python code (like insecure deserialization, command injection, hardcoded secrets, OWASP Top 10) and potential misconfigurations or secrets in other file types. You also check for known vulnerabilities in project dependencies.
    It is very important that you try to identify all vulnerabilities and not only the most obvious ones. Do not only look for vulnerabilities of the categories mentioned above!

    You do this by performing step-by-step analysis. You are allowed to use the following tools:

    - load_files(path: str) -> str: Loads and returns the contents of ALL non-hidden files from a specified file or recursively from a directory. The format is a list of (file_path, file_content) tuples. Content for binary files or files too large might be a placeholder. Be mindful of the content type of each file when deciding which other tools to use.
    - static_analysis(code: str) -> str: Runs static security scanners (e.g., Bandit) on PYTHON CODE and returns a list of flagged lines with issue types and severity. CRITICAL: Only pass the content of Python (.py) files to this tool. Do NOT pass content from non-Python files.
    - parse_ast(code: str) -> str: Parses PYTHON CODE into an abstract syntax tree and extracts function names, inputs, and risky constructs (e.g., eval, exec, os.system). CRITICAL: Only pass the content of Python (.py) files to this tool. Do NOT pass content from non-Python files.
    - check_dependencies(project_path: str) -> str: Scans project dependency files (e.g., requirements.txt, poetry.lock, etc.) using 'pip-audit' to find known vulnerabilities in third-party packages. The 'project_path' should be the root directory of the project that contains these dependency files. If the initial analysis target was a directory, use that directory as 'project_path'. If the initial analysis target was a single file, use its *containing directory* as 'project_path' for this tool. Returns a JSON string with findings.
    - doc_search_with_brave(query: str) -> str: Performs a live search using the Brave Search API to retrieve recent documentation and best practices from sources like OWASP, CWE, and security blogs. The results are summarized using your reasoning ability. Use this tool when you need external context or to validate the risk or mitigation of a specific pattern identified in ANY file type.
    - suggest_fix(issue: str, code_snippet: str) -> str: Proposes a secure version of a code snippet that mitigates a vulnerability. This is primarily for Python code, but can be adapted for configuration files if the issue is simple (e.g., removing a hardcoded secret). Clearly state if the fix applies to a non-Python file.

    You may call multiple tools per turn (for parallel execution), for up to 15 turns, before giving your final answer.

    When analyzing a directory with multiple files, or a single file that might be part of a larger project:
    - First, load all files using `load_files` to get a comprehensive overview of the project.
    - Review the list of loaded files and their paths. For each file:
        - If it's a Python file (.py), plan to use `static_analysis` and `parse_ast` on its content.
        - If it's a known dependency file (requirements.txt, poetry.lock, etc.), remember its path for use with `check_dependencies`.
        - For ALL file types (including configurations like .json, .yaml, .ini, .toml, Dockerfiles, shell scripts, etc.), manually review their content for hardcoded secrets, weak configurations, sensitive data exposure, or any other security-relevant information. Use `doc_search_with_brave` if you need more context on a specific technology or pattern found.
    - Determine the effective 'project_path' for dependency checking:
        - If the input `CODE_PATH` was a directory, that directory is the 'project_path'.
        - If the input `CODE_PATH` was a file path, its containing directory should be considered for `check_dependencies`.
    - Pay close attention to how different components (Python files, configuration files, scripts) might interact to create vulnerabilities.
    - Trace data flow across files and components.
    - Your analysis should be thorough.

    In each turn, respond in the following format:

    <think>
    [Explain what you're doing next, what you need, or what issue you're focusing on. Explicitly state which file(s) you are examining and if you intend to pass specific file content to a tool, confirm its type is appropriate for that tool (e.g., "Passing content of 'utils.py' to static_analysis as it is Python code." or "Reviewing 'config.json' for hardcoded secrets."). If dependency files are present, explicitly state the 'project_path' you intend to use for `check_dependencies`.]
    </think>
    <tools>
    [
        {
            "name": "tool_name",
            "args": {"arg1": "value1", "arg2": "value2"}
        },
        {
            "name": "another_tool_name", 
            "args": {"arg1": "value1"}
        }
    ]
    </tools>

    You can call multiple tools in parallel by including multiple tool objects in the tools array. This allows for efficient concurrent execution of independent operations like analyzing different files or running multiple types of analysis on the same code.

    Examples of effective parallel tool usage:
    - Analyzing multiple Python files simultaneously with static_analysis and parse_ast
    - Running dependency checks while analyzing source files
    - Searching for documentation while performing static analysis
    - Generating fixes for multiple vulnerabilities at once

    Use parallel execution when tools don't depend on each other's output. Use sequential execution when one tool's output is needed as input for another tool.

    When you are done, provide a clear and structured security review in the following format:

    <answer>
    For a single file analysis:
    <file>
    <name>filename.py</name>
    # File Analysis Report

    ## 1. Summary of File/Code Purpose
    [Provide a clear and concise description of what this file does and its role in the project]

    ## 2. Detected Vulnerabilities
    ### High Severity Issues
    - **Issue Title** (Line X)
      - Description of the vulnerability
      - Why it's dangerous
      - Relevant CVE/CWE/OWASP references
      - Impact assessment

    ### Medium Severity Issues
    - **Issue Title** (Line X)
      - Description of the vulnerability
      - Why it's dangerous
      - Relevant CVE/CWE/OWASP references
      - Impact assessment

    ### Low Severity Issues
    - **Issue Title** (Line X)
      - Description of the vulnerability
      - Why it's dangerous
      - Relevant CVE/CWE/OWASP references
      - Impact assessment

    ## 3. Suggested Fixes
    ### Fix for [Issue Title]
    ```python
    # Before
    vulnerable_code_here

    # After
    secure_code_here
    ```
    - Explanation of the fix
    - Why it's more secure
    - Additional security considerations
    </file>

    For multiple files/directory analysis:
    <file>
    <name>summary</name>
    # Project Security Summary

    ## 1. Overall Project Summary
    - Project purpose and main functionality
    - Key components and their relationships
    - Technology stack overview

    ## 2. Most Critical Vulnerabilities Found
    ### High Priority Issues
    - **Issue Title** (File: X, Line: Y)
      - Brief description
      - Severity level
      - Potential impact

    ### Medium Priority Issues
    - **Issue Title** (File: X, Line: Y)
      - Brief description
      - Severity level
      - Potential impact

    ## 3. Summary of Dependency Vulnerabilities
    - List of vulnerable dependencies
    - Severity levels
    - Recommended updates/alternatives

    ## 4. General Recommendations
    - Security best practices to implement
    - Architectural improvements
    - Development process suggestions
    </file>

    <file>
    <name>file1.py</name>
    # File Analysis Report

    ## 1. Summary of File/Code Purpose
    [Provide a clear and concise description of what this file does and its role in the project]

    ## 2. Detected Vulnerabilities
    ### High Severity Issues
    - **Issue Title** (Line X)
      - Description of the vulnerability
      - Why it's dangerous
      - Relevant CVE/CWE/OWASP references
      - Impact assessment

    ### Medium Severity Issues
    - **Issue Title** (Line X)
      - Description of the vulnerability
      - Why it's dangerous
      - Relevant CVE/CWE/OWASP references
      - Impact assessment

    ### Low Severity Issues
    - **Issue Title** (Line X)
      - Description of the vulnerability
      - Why it's dangerous
      - Relevant CVE/CWE/OWASP references
      - Impact assessment

    ## 3. Suggested Fixes
    ### Fix for [Issue Title]
    ```python
    # Before
    vulnerable_code_here

    # After
    secure_code_here
    ```
    - Explanation of the fix
    - Why it's more secure
    - Additional security considerations
    </file>

    <file>
    <name>file2.py</name>
    1. Summary of File/Code Purpose
    2. Detected Vulnerabilities
    3. Suggested Fixes
    </file>
    </answer>

    The answer should be well-structured and easily readable.
    If analyzing multiple files/a directory, first generate a "summary" report. This summary should highlight:
      - The overall purpose of the project/directory.
      - The most critical vulnerabilities found across ALL file types.
      - A summary of any known vulnerabilities found in third-party dependencies.
      - General recommendations or patterns observed.
    Then, provide a detailed report for each *relevant* file analyzed (prioritize Python files and any non-Python files where issues were found).
    Use the name "summary" for the summary section. If only a single file was analyzed, omit the summary block.
    """
    return (system_prompt,)


@app.cell
def _(
    BRAVE_API_KEY,
    List,
    Tuple,
    Union,
    aiohttp,
    ast,
    asyncio,
    client,
    concurrent,
    json,
    os,
    requests,
    subprocess,
    sys,
    tempfile,
):
    async def load_files(path: Union[str, os.PathLike]) -> List[Tuple[str, str]]:
        """Load all non-hidden files from a path, returning [(file_path, content), ...]"""
        files = []
        path = os.path.normpath(path)

        async def read_file(file_path: str) -> str:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                return f"[Error reading {os.path.basename(file_path)}: {e}]"

        if os.path.isfile(path):
            files.append((path, await read_file(path)))
        elif os.path.isdir(path):
            # Collect all file paths first
            file_paths = []
            for root, dirs, filenames in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for filename in filenames:
                    if not filename.startswith("."):
                        full_path = os.path.join(root, filename)
                        if os.path.isfile(full_path):
                            file_paths.append(full_path)
            
            # Read all files concurrently
            tasks = [read_file(file_path) for file_path in file_paths]
            file_contents = await asyncio.gather(*tasks)
            files = list(zip(file_paths, file_contents))
        else:
            raise ValueError(f"Invalid path: {path}")

        if not files and (os.path.isfile(path) or os.path.isdir(path)):
            print(f"No non-hidden files found in '{path}'")

        return files


    async def static_analysis(code: str) -> list:
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w+", delete=False
        ) as tmp:
            tmp.write(code)
            tmp.flush()
            result = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "bandit", "-f", "json", tmp.name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            try:
                output = json.loads(stdout.decode("utf-8"))
                return [
                    {
                        "line": item["line_number"],
                        "issue": item["issue_text"],
                        "severity": item["issue_severity"],
                        "confidence": item["issue_confidence"],
                        "id": item["test_id"],
                    }
                    for item in output.get("results", [])
                ]
            except Exception as e:
                return [{"error": str(e)}]


    async def parse_ast(code: str) -> dict:
        # Run CPU-bound AST parsing in a thread pool
        def _parse_ast_sync(code: str) -> dict:
            tree = ast.parse(code)
            functions = []
            risky_calls = []
            imports = []

            class Analyzer(ast.NodeVisitor):
                def visit_FunctionDef(self, node):
                    functions.append(node.name)
                    self.generic_visit(node)

                def visit_Call(self, node):
                    if isinstance(node.func, ast.Attribute):
                        func_name = f"{ast.unparse(node.func.value)}.{node.func.attr}"
                        if func_name in [
                            "os.system",
                            "eval",
                            "exec",
                            "pickle.load",
                            "subprocess.Popen",
                        ]:
                            risky_calls.append(
                                {
                                    "line": node.lineno,
                                    "call": func_name,
                                    "arg": ast.unparse(node.args[0])
                                    if node.args
                                    else "",
                                }
                            )
                    self.generic_visit(node)

                def visit_Import(self, node):
                    for alias in node.names:
                        imports.append(alias.name)

                def visit_ImportFrom(self, node):
                    imports.append(node.module)

            Analyzer().visit(tree)

            return {
                "functions": functions,
                "risky_calls": risky_calls,
                "imports": imports,
            }
        
        # Run in thread pool for better async behavior
        with concurrent.futures.ThreadPoolExecutor() as executor:
            return await asyncio.get_event_loop().run_in_executor(executor, _parse_ast_sync, code)


    async def brave_search(query: str) -> list[str]:
        url = "https://api.search.brave.com/res/v1/web/search"
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": BRAVE_API_KEY,
        }
        params = {"q": query, "count": 5, "freshness": "Month"}

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params) as resp:
                resp.raise_for_status()
                data = await resp.json()
                results = data.get("web", {}).get("results", [])
                return [
                    r.get("title", "") + "\n" + r.get("description", "") for r in results
                ]


    async def doc_search_with_brave(query: str, model: str = "gpt-4.1") -> str:
        results = await brave_search(query)
        context = "\n\n".join(results)

        prompt = (
            "You are a security expert. Answer the following question using the information "
            "from recent search results:\n\n"
            f"Search results:\n{context}\n\n"
            f"Question: {query}\n\n"
            "Answer:"
        )

        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content.strip()


    async def suggest_fix(
        issue: str, code_snippet: str, model_name: str = "gpt-4.1"
    ) -> str:
        prompt = (
            "You are a secure code advisor.\n"
            f"The following code has a security issue: {issue}.\n"
            "Suggest a safer version of the code and explain why it's better.\n\n"
            f"Code:\n{code_snippet}"
        )

        response = await client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
        )

        return response.choices[0].message.content


    async def check_dependencies(project_path: str) -> str:
        """
        Checks project dependencies for vulnerabilities using pip-audit.
        Returns JSON string with audit results and metadata.
        """
        project_path = os.path.abspath(project_path)

        # Find dependency file to audit
        dep_files = {
            "requirements.txt": ["--no-deps", "--disable-pip", "-r"],
            "uv.lock": ["--no-deps", "--disable-pip", "-r"],
            "pyproject.toml": [],
            "poetry.lock": [],
            "pdm.lock": []
        }

        # Try to find a dependency file
        dep_file = None
        for file, flags in dep_files.items():
            if os.path.exists(os.path.join(project_path, file)):
                dep_file = file
                extra_flags = flags
                break

        if not dep_file:
            return json.dumps({
                "status": "No dependency files found to audit",
                "source_checked": project_path
            })

        # Build command
        cmd = [sys.executable, "-m", "pip_audit", "--progress-spinner", "off"]
        if extra_flags:
            cmd.extend(extra_flags)
            cmd.append(os.path.join(project_path, dep_file))

        try:
            # Run pip-audit
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=project_path,
            )
            stdout, stderr = await process.communicate()

            # Build response
            response = {
                "source_audited": f"Audit of {dep_file}",
                "command_used": " ".join(cmd),
                "return_code": process.returncode,
                "stdout": stdout.decode("utf-8").strip() or "N/A",
                "stderr": stderr.decode("utf-8").strip() or "N/A"
            }

            # Add status message
            if process.returncode != 0:
                response["status_message"] = "Vulnerabilities found or error occurred"
            else:
                response["status_message"] = "No vulnerabilities found" if "No known vulnerabilities found" in stdout.decode("utf-8") else "Review stdout for details"

            return json.dumps(response, indent=2)
        except Exception as e:
            return json.dumps({
                "error": f"Unexpected error: {e}",
                "source_checked": project_path,
                "command_attempted": " ".join(cmd)
            })
    return (
        check_dependencies,
        doc_search_with_brave,
        load_files,
        parse_ast,
        static_analysis,
        suggest_fix,
    )


@app.cell
def _(Any, CODE_PATH, Dict, Optional, json, markdown, os, re):
    def parse_thinking_from_response(response: str) -> Optional[str]:
        """Extract the <think> block from the LLM response."""
        match = re.search(r"<think>(.*?)</think>", response, re.DOTALL)
        return match.group(1).strip() if match else None


    def parse_tool_from_response(response: str) -> Optional[List[Dict[str, Any]]]:
        """Extract the <tools> call as a list of dictionaries from the LLM response."""
        match = re.search(r"<tools>(.*?)</tools>", response, re.DOTALL)
        if not match:
            # Fallback to old format for backward compatibility
            match = re.search(r"<tool>(.*?)</tool>", response, re.DOTALL)
            if not match:
                return None
            try:
                single_tool = json.loads(match.group(1))
                return [single_tool]
            except json.JSONDecodeError as e:
                print(f"JSON parsing error in <tool>: {e}")
                return None
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError as e:
            print(f"JSON parsing error in <tools>: {e}")
            return None


    def parse_answer_from_response(response: str) -> Optional[str]:
        """Extract the <answer> block from the LLM response."""
        match = re.search(r"<answer>(.*?)</answer>", response, re.DOTALL)
        return match.group(1).strip() if match else None

    def sanitize_filename(name: str) -> str:
        """Sanitize a filename for safe filesystem usage.

        Transforms input into a clean, URL-friendly format with SecureSage prefix.
        Example: 'path/to/file.py' -> 'SecureSage-Report-path-to-file'

        Args:
            name: Original filename or path to sanitize

        Returns:
            Sanitized filename, max 250 chars, prefixed with 'SecureSage-Report-'
        """
        PREFIX = "SecureSage-Report-"
        MAX_LENGTH = 250

        # Handle summary case
        if name.lower() == "summary":
            return f"{PREFIX}summary"

        # Remove leading path components
        name = re.sub(r"^[./\\]+", "", name)
        name = re.sub(r"^[./\\]+", "", name)  # Handle double leading slashes

        # Convert to slug format
        slug = name.split(".")[0]
        slug = slug.lower()
        slug = re.sub(r"[^a-z0-9\-]+", "-", slug)
        slug = re.sub(r"-+", "-", slug)
        slug = slug.strip("-")

        # Handle empty result
        if not slug:
            slug = "untitled-report"

        return f"{PREFIX}{slug}"[:MAX_LENGTH]


    def split_and_write_answers(
        raw_answer: str,
        output_dir: str = "reports",
        generate_md: bool = True,
        generate_html: bool = True
    ) -> None:
        """
        Splits a SecureSage response block into individual sections per file and
        writes each to its own .md and/or .html file.
        Sections should be wrapped in <file><name>filename</name>content</file> tags.
        If no filename is found, a default name will be generated.
        """
        if not generate_md and not generate_html:
            print("Info: No output format selected (generate_md and generate_html are both False). No reports written.")
            return

        if os.path.isfile(CODE_PATH):
            folder_name = os.path.splitext(os.path.basename(CODE_PATH))[0]
        else:
            folder_name = os.path.basename(os.path.normpath(CODE_PATH))

        folder_name = re.sub(r'[^a-zA-Z0-9]', '_', folder_name).lower()
        folder_name = re.sub(r'_+', '_', folder_name).strip('_')

        analysis_dir = os.path.join(output_dir, folder_name)
        os.makedirs(analysis_dir, exist_ok=True)

        file_pattern = r"<file>\s*<name>(.*?)</name>(.*?)</file>"
        sections = re.findall(file_pattern, raw_answer, re.DOTALL)

        for i, (file_name, content) in enumerate(sections):
            file_name = file_name.strip()
            content = content.strip()

            if not file_name:
                title_match = re.search(r"^#\s*(.+)$", content, re.MULTILINE)
                if title_match:
                    file_name = title_match.group(1).strip()
                else:
                    first_line = content.split('\n')[0].strip()
                    if first_line and len(first_line) < 50:
                        file_name = first_line
                    else:
                        file_name = f"report_{i+1}"

            if file_name.lower() == "summary":
                safe_name_base = "summary"
            else:
                base_name = os.path.splitext(os.path.basename(file_name))[0]
                base_name = re.sub(r'(report|analysis|security|vulnerability|audit)[-_]?', '', base_name, flags=re.IGNORECASE)
                safe_name_base = re.sub(r'[^a-zA-Z0-9]', '_', base_name).lower()
                safe_name_base = re.sub(r'_+', '_', safe_name_base).strip('_')
                if len(safe_name_base) > 30:
                    safe_name_base = safe_name_base[:30]

            if generate_md:
                md_file_path = os.path.join(analysis_dir, f"{safe_name_base}.md")
                try:
                    with open(md_file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                        f.write("\n")
                except Exception as e:
                    print(f"Error writing MD file: {e}")

            if generate_html:
                html_file_path = os.path.join(analysis_dir, f"{safe_name_base}.html")
                try:
                    # Convert the Markdown content to HTML
                    html_content = markdown.markdown(
                        content, 
                        extensions=['fenced_code', 'tables', 'nl2br', 'sane_lists']
                    )

                    # Enhanced HTML template with modern styling
                    html_template = f"""<!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>{file_name}</title>
                        <style>
                            :root {{
                                --primary-color: #2c3e50;
                                --secondary-color: #3498db;
                                --accent-color: #e74c3c;
                                --background-color: #f8f9fa;
                                --text-color: #2c3e50;
                                --code-bg: #f1f1f1;
                                --border-color: #dee2e6;
                            }}

                            body {{
                                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                                line-height: 1.6;
                                margin: 0;
                                padding: 0;
                                background-color: var(--background-color);
                                color: var(--text-color);
                            }}

                            .container {{
                                max-width: 1000px;
                                margin: 0 auto;
                                padding: 2rem;
                                background: white;
                                box-shadow: 0 0 20px rgba(0,0,0,0.1);
                                min-height: 100vh;
                            }}

                            h1 {{
                                color: var(--primary-color);
                                border-bottom: 3px solid var(--secondary-color);
                                padding-bottom: 0.5rem;
                                margin-top: 0;
                                font-size: 1.8rem;
                            }}

                            h2 {{
                                color: var(--primary-color);
                                margin-top: 2rem;
                                border-left: 4px solid var(--secondary-color);
                                padding-left: 1rem;
                                font-size: 1.5rem;
                            }}

                            h3 {{
                                color: var(--primary-color);
                                margin-top: 1.5rem;
                                font-size: 1.2rem;
                            }}

                            pre {{
                                background-color: var(--code-bg);
                                padding: 1.5rem;
                                border-radius: 8px;
                                overflow-x: auto;
                                border: 1px solid var(--border-color);
                                margin: 1rem 0;
                            }}

                            code {{
                                font-family: 'Fira Code', 'Consolas', monospace;
                                font-size: 0.9em;
                                background-color: var(--code-bg);
                                padding: 0.2em 0.4em;
                                border-radius: 3px;
                            }}

                            pre code {{
                                padding: 0;
                                background: none;
                            }}

                            table {{
                                border-collapse: collapse;
                                width: 100%;
                                margin: 1.5rem 0;
                                border-radius: 8px;
                                overflow: hidden;
                                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                            }}

                            th, td {{
                                padding: 1rem;
                                text-align: left;
                                border: 1px solid var(--border-color);
                            }}

                            th {{
                                background-color: var(--primary-color);
                                color: white;
                                font-weight: 600;
                            }}

                            tr:nth-child(even) {{
                                background-color: #f8f9fa;
                            }}

                            tr:hover {{
                                background-color: #f1f1f1;
                            }}

                            .severity-high {{
                                color: #dc3545;
                                font-weight: bold;
                            }}

                            .severity-medium {{
                                color: #fd7e14;
                                font-weight: bold;
                            }}

                            .severity-low {{
                                color: #28a745;
                                font-weight: bold;
                            }}

                            .vulnerability {{
                                background-color: #fff3cd;
                                border-left: 4px solid #ffc107;
                                padding: 1rem;
                                margin: 1rem 0;
                                border-radius: 0 4px 4px 0;
                            }}

                            .fix-suggestion {{
                                background-color: #d4edda;
                                border-left: 4px solid #28a745;
                                padding: 1rem;
                                margin: 1rem 0;
                                border-radius: 0 4px 4px 0;
                            }}

                            .summary {{
                                background-color: #e2e3e5;
                                border-left: 4px solid #6c757d;
                                padding: 1rem;
                                margin: 1rem 0;
                                border-radius: 0 4px 4px 0;
                            }}

                            @media (max-width: 768px) {{
                                .container {{
                                    padding: 1rem;
                                }}

                                pre {{
                                    padding: 1rem;
                                }}

                                th, td {{
                                    padding: 0.75rem;
                                }}
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            {html_content}
                        </div>
                    </body>
                    </html>"""
                    with open(html_file_path, "w", encoding="utf-8") as f:
                        f.write(html_template)
                except Exception as e:
                    print(f"Error writing HTML file: {e}")

        print(f"\nReports have been saved to: {analysis_dir}")

    return (
        parse_answer_from_response,
        parse_thinking_from_response,
        parse_tool_from_response,
        split_and_write_answers,
    )


@app.cell
def _(
    CODE_PATH,
    asyncio,
    check_dependencies,
    client,
    doc_search_with_brave,
    json,
    load_files,
    model,
    os,
    parse_answer_from_response,
    parse_ast,
    parse_thinking_from_response,
    parse_tool_from_response,
    split_and_write_answers,
    static_analysis,
    suggest_fix,
    system_prompt,
):
    # Agent memory
    messages = [{"role": "system", "content": system_prompt}]
    max_turns = 17

    tool_registry = {
        "load_files": load_files,
        "static_analysis": static_analysis,
        "parse_ast": parse_ast,
        "doc_search_with_brave": doc_search_with_brave,
        "suggest_fix": suggest_fix,
        "check_dependencies": check_dependencies,
    }


    user_input = f"Please analyze {CODE_PATH} for vulnerabilities. Make sure to check everything and write a very pretty and detailed report. "
    messages.append({"role": "user", "content": user_input})

    file_name = os.path.basename(CODE_PATH).replace(".py", "")

    print(f"Agent starting to analyze... {CODE_PATH}")
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.progress import Progress
    import time

    console = Console()

    async def run_agent():
        tool_call_count = 1
        while tool_call_count < max_turns:
            console.print(Panel.fit(
                f"[bold blue]Agent Turn {tool_call_count}[/bold blue]",
                border_style="blue"
            ))

            with Progress() as progress:
                task = progress.add_task("[cyan]Thinking...", total=None)
                response = await client.chat.completions.create(
                    model=model,
                    messages=messages,
                )

            reply = response.choices[0].message.content
            messages.append({"role": "assistant", "content": reply})

            thought = parse_thinking_from_response(reply)
            if thought:
                console.print(Panel(
                    thought,
                    title="[bold yellow]Agent Thought[/bold yellow]",
                    border_style="yellow"
                ))

            answer = parse_answer_from_response(reply)
            if answer:
                split_and_write_answers(answer)
                console.print("[bold green]Report successfully written to markdown![/bold green]")
                break

            tool_calls = parse_tool_from_response(reply)
            if not tool_calls:
                console.print("[bold red]No tool calls found. Exiting.[/bold red]")
                console.print(Panel(reply, title="[bold red]Last Response[/bold red]"))
                break

            # Display all tool calls
            for i, tool_call in enumerate(tool_calls):
                tool_name = tool_call["name"]
                args = tool_call["args"]
                console.print(Panel(
                    f"[bold]Tool {i+1}:[/bold] {tool_name}\n[bold]Arguments:[/bold]\n{json.dumps(args, indent=2)}",
                    title=f"[bold blue]Tool Call {i+1}/{len(tool_calls)}[/bold blue]",
                    border_style="blue"
                ))

            # Execute all tools in parallel
            async def execute_tool(tool_call):
                tool_name = tool_call["name"]
                args = tool_call["args"]
                
                tool_func = tool_registry.get(tool_name)
                if not tool_func:
                    return {"error": f"Unknown tool: {tool_name}"}
                
                try:
                    result = await tool_func(**args)
                    return {"tool": tool_name, "result": result}
                except Exception as e:
                    return {"tool": tool_name, "error": str(e)}

            with Progress() as progress:
                task = progress.add_task("[cyan]Executing tools...", total=None)
                results = await asyncio.gather(*[execute_tool(tool_call) for tool_call in tool_calls])

            # Display results
            combined_results = {}
            for i, result in enumerate(results):
                tool_name = result.get("tool", f"tool_{i}")
                if "error" in result:
                    console.print(f"[bold red]Tool {tool_name} execution failed: {result['error']}[/bold red]")
                    combined_results[tool_name] = {"error": result["error"]}
                else:
                    console.print(Panel(
                        Syntax(json.dumps(result["result"], indent=2), "json", theme="monokai"),
                        title=f"[bold green]Tool Result: {tool_name}[/bold green]",
                        border_style="green"
                    ))
                    combined_results[tool_name] = result["result"]

            messages.append({"role": "user", "content": json.dumps(combined_results, indent=2)})
            tool_call_count += 1
            await asyncio.sleep(0.5)

    # Run the async agent
    asyncio.run(run_agent())
    return


@app.cell
def _():
    return


if __name__ == "__main__":
    app.run()
