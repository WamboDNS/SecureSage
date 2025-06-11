import marimo

__generated_with = "0.13.15"
app = marimo.App(
    width="medium",
    app_title="SecureSage",
    auto_download=["ipynb"],
)


@app.cell
def _():
    CODE_PATH = "./example_code/code4.py"
    return (CODE_PATH,)


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
    import sys
    import markdown
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
        ast,
        json,
        markdown,
        os,
        re,
        requests,
        subprocess,
        sys,
        tempfile,
    )


@app.cell
def _(OPENAI_API_KEY, OpenAI):
    model = "gpt-4.1"
    base_URL = "https://api.openai.com/v1"
    client = OpenAI(api_key=OPENAI_API_KEY, base_url=base_URL)
    return client, model


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

    You may call one tool per turn, for up to 15 turns, before giving your final answer.

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
    <tool>
    JSON with the following fields:
    - name: The name of the tool to call
    - args: A dictionary of arguments to pass to the tool (must be valid JSON)
    </tool>

    When you are done, provide a clear and structured security review in the following format:

    <answer>
    Name of the file being analyzed: $FILE_NAME
    1. Summary of File/Code Purpose (If $FILE_NAME is "summary", this should be an overall project summary)
    2. Detected Vulnerabilities (with file paths, line numbers if applicable, and severity) and explanation of each issue (why it's dangerous, relevant CVE/CWE/OWASP ref). Clearly distinguish between issues in Python code versus issues in configuration or other file types. Explicitly mention if a vulnerability spans multiple files/components. Include a section for "Dependency Vulnerabilities" if `check_dependencies` was used and found issues.
    3. Suggested Fixes (with example code/configuration and links if possible and helpful). Specify which file the fix applies to.
    ---------------------------------
    </answer>

    The answer should be well-structured and easily readable.
    If analyzing multiple files/a directory, first generate a "summary" report. This summary should highlight:
      - The overall purpose of the project/directory.
      - The most critical vulnerabilities found across ALL file types.
      - A summary of any known vulnerabilities found in third-party dependencies.
      - General recommendations or patterns observed.
    Then, provide a detailed report for each *relevant* file analyzed (prioritize Python files and any non-Python files where issues were found). All reports (summary and per-file) should be in one answer block, separated by "---------------------------------".
    Use the name "summary" for the summary section. If only a single file was analyzed, omit the summary block.
    """
    return (system_prompt,)


@app.cell
def _(
    BRAVE_API_KEY,
    List,
    Tuple,
    Union,
    ast,
    client,
    json,
    os,
    requests,
    subprocess,
    sys,
    tempfile,
):
    def load_files(path: Union[str, os.PathLike]) -> List[Tuple[str, str]]:
        """Load all non-hidden files from a path, returning [(file_path, content), ...]"""
        files = []
        path = os.path.normpath(path)

        def read_file(file_path: str) -> str:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read()
            except UnicodeDecodeError:
                return f"[Binary file: {os.path.basename(file_path)}]"
            except Exception as e:
                return f"[Error reading {os.path.basename(file_path)}: {e}]"

        if os.path.isfile(path):
            files.append((path, read_file(path)))
        elif os.path.isdir(path):
            for root, dirs, filenames in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for filename in filenames:
                    if not filename.startswith("."):
                        full_path = os.path.join(root, filename)
                        if os.path.isfile(full_path):
                            files.append((full_path, read_file(full_path)))
        else:
            raise ValueError(f"Invalid path: {path}")

        if not files and (os.path.isfile(path) or os.path.isdir(path)):
            print(f"No non-hidden files found in '{path}'")

        return files


    def static_analysis(code: str) -> list:
        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w+", delete=False
        ) as tmp:
            tmp.write(code)
            tmp.flush()
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-f", "json", tmp.name], capture_output=True, text=True
            )
            try:
                output = json.loads(result.stdout)
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


    def parse_ast(code: str) -> dict:
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


    def brave_search(query: str) -> list[str]:
        url = "https://api.search.brave.com/res/v1/web/search"
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": BRAVE_API_KEY,
        }
        params = {"q": query, "count": 5, "freshness": "Month"}

        resp = requests.get(url, headers=headers, params=params)
        data = resp.json()
        results = data.get("web", {}).get("results", [])
        return [
            r.get("title", "") + "\n" + r.get("description", "") for r in results
        ]


    def doc_search_with_brave(query: str, model: str = "gpt-4.1") -> str:
        results = brave_search(query)
        context = "\n\n".join(results)

        prompt = (
            "You are a security expert. Answer the following question using the information "
            "from recent search results:\n\n"
            f"Search results:\n{context}\n\n"
            f"Question: {query}\n\n"
            "Answer:"
        )

        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content.strip()


    def suggest_fix(
        issue: str, code_snippet: str, model_name: str = "gpt-4.1"
    ) -> str:
        prompt = (
            "You are a secure code advisor.\n"
            f"The following code has a security issue: {issue}.\n"
            "Suggest a safer version of the code and explain why it's better.\n\n"
            f"Code:\n{code_snippet}"
        )

        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
        )

        return response.choices[0].message.content


    def check_dependencies(project_path: str) -> str:
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
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=project_path,
                check=False
            )

            # Build response
            response = {
                "source_audited": f"Audit of {dep_file}",
                "command_used": " ".join(cmd),
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr.strip() or "N/A"
            }

            # Add status message
            if result.returncode != 0:
                response["status_message"] = "Vulnerabilities found or error occurred"
            else:
                response["status_message"] = "No vulnerabilities found" if "No known vulnerabilities found" in result.stdout else "Review stdout for details"

            return json.dumps(response, indent=2)

        except FileNotFoundError:
            return json.dumps({
                "error": f"pip-audit not found in {sys.prefix}",
                "source_checked": project_path,
                "command_attempted": " ".join(cmd)
            })
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
def _(Any, Dict, Optional, json, markdown, os, re):
    def parse_thinking_from_response(response: str) -> Optional[str]:
        """Extract the <think> block from the LLM response."""
        match = re.search(r"<think>(.*?)</think>", response, re.DOTALL)
        return match.group(1).strip() if match else None


    def parse_tool_from_response(response: str) -> Optional[Dict[str, Any]]:
        """Extract the <tool> call as a dictionary from the LLM response."""
        match = re.search(r"<tool>(.*?)</tool>", response, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError as e:
            print(f"JSON parsing error in <tool>: {e}")
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
        slug = name.split(".")[0]  # Remove extension
        slug = slug.lower()
        slug = re.sub(r"[^a-z0-9\-]+", "-", slug)  # Replace non-alphanumeric with hyphens
        slug = re.sub(r"-+", "-", slug)  # Collapse multiple hyphens
        slug = slug.strip("-")  # Remove leading/trailing hyphens

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
        Sections must start with:   Name of the file being analyzed: <filename>
        and end with:               ---------------------------------
        """
        if not generate_md and not generate_html:
            print("Info: No output format selected (generate_md and generate_html are both False). No reports written.")
            return

        os.makedirs(output_dir, exist_ok=True)

        # Split at each delimiter
        # Add a filter to remove empty strings that can result from trailing delimiters
        sections = [s.strip() for s in raw_answer.strip().split("---------------------------------") if s.strip()]

        for section_content in sections:
            # Find the file name
            file_match = re.search(
                r"Name of the file being analyzed:\s*(.+)", section_content # Use section_content
            )
            if not file_match:
                print(f"Warning: Could not find 'Name of the file being analyzed:' in section. Skipping block:\n---\n{section_content[:200]}...\n---")
                continue 

            file_name_from_report = file_match.group(1).strip()
            safe_name_base = sanitize_filename(file_name_from_report) # Get base for filenames

            report_title = f"# SecureSage Security Report: {file_name_from_report}\n\n"
            # The content for the file should not include the "Name of the file being analyzed:" line itself,
            # if we are already putting it in the title or if the safe_name_base is enough.
            # Let's keep the section_content as is for now, as it's structured by the LLM.

            if generate_md:
                md_file_path = os.path.join(output_dir, f"{safe_name_base}.md")
                try:
                    with open(md_file_path, "w", encoding="utf-8") as f:
                        # f.write(report_title) # The report_title might be redundant if section_content already has it
                        f.write(section_content) # section_content already contains "Name of the file..."
                        f.write("\n")
                except Exception as e:
                    print(e)

            if generate_html:
                html_file_path = os.path.join(output_dir, f"{safe_name_base}.html")
                try:
                    # Convert the Markdown section content to HTML
                    # You can add extensions for more features, e.g., 'markdown.extensions.fenced_code' for code blocks
                    # 'markdown.extensions.tables' for tables, etc.
                    html_content = markdown.markdown(
                        section_content, 
                        extensions=['fenced_code', 'tables', 'nl2br'] # nl2br for line breaks
                    )

                    # Basic HTML structure
                    html_template = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SecureSage Report: {file_name_from_report}</title>
        <style>
            body {{ font-family: sans-serif; line-height: 1.6; margin: 20px; max-width: 800px; margin-left: auto; margin-right: auto; }}
            h1, h2, h3 {{ color: #333; }}
            pre {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            code {{ font-family: monospace; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 1em; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        {html_content}
    </body>
    </html>"""
                    with open(html_file_path, "w", encoding="utf-8") as f:
                        f.write(html_template)
                except Exception as e:
                    print(e)

    return (
        parse_answer_from_response,
        parse_thinking_from_response,
        parse_tool_from_response,
        split_and_write_answers,
    )


@app.cell
def _(
    CODE_PATH,
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
    tool_call_count = 1
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

    while tool_call_count < max_turns:
        console.print(Panel.fit(
            f"[bold blue]Agent Turn {tool_call_count}[/bold blue]",
            border_style="blue"
        ))

        with Progress() as progress:
            task = progress.add_task("[cyan]Thinking...", total=None)
            response = client.chat.completions.create(
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

        tool_call = parse_tool_from_response(reply)
        if not tool_call:
            console.print("[bold red]No tool call found. Exiting.[/bold red]")
            console.print(Panel(reply, title="[bold red]Last Response[/bold red]"))
            break

        tool_name = tool_call["name"]
        args = tool_call["args"]

        console.print(Panel(
            f"[bold]Tool:[/bold] {tool_name}\n[bold]Arguments:[/bold]\n{json.dumps(args, indent=2)}",
            title="[bold blue]Tool Call[/bold blue]",
            border_style="blue"
        ))

        tool_func = tool_registry.get(tool_name)
        if not tool_func:
            console.print(f"[bold red]Unknown tool: {tool_name}[/bold red]")
            break

        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Executing tool...", total=None)
                result = tool_func(**args)
        except Exception as e:
            result = {"error": str(e)}
            console.print(f"[bold red]Tool execution failed: {str(e)}[/bold red]")

        console.print(Panel(
            Syntax(json.dumps(result, indent=2), "json", theme="monokai"),
            title="[bold green]Tool Result[/bold green]",
            border_style="green"
        ))

        messages.append({"role": "user", "content": json.dumps(result, indent=2)})
        tool_call_count += 1
        time.sleep(0.5)
    return


@app.cell
def _():
    return


if __name__ == "__main__":
    app.run()
