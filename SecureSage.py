import marimo

__generated_with = "0.13.15"
app = marimo.App(width="medium", app_title="SecureSage")


@app.cell
def _():
    CODE_PATH = "./example_code/test_project/"
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
    Then, provide a detailed report for each *significant* file analyzed (prioritize Python files and any non-Python files where issues were found). All reports (summary and per-file) should be in one answer block, separated by "---------------------------------".
    Use the name "summary" for the summary section. If only a single file was analyzed, omit the summary block.
    </answer>
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
        """
        Recursively loads all non-hidden files from a file or directory.
        Attempts to read files as UTF-8 text. If a file cannot be decoded,
        a placeholder message is returned as its content.

        Returns:
            List of tuples: [(file_path, file_content), ...]
        """
        files_to_load = []
        normalized_path = os.path.normpath(path)

        def read_file_content(file_path: str) -> str:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read()
            except UnicodeDecodeError:
                return f"[Cannot decode file as UTF-8 text: {os.path.basename(file_path)} - likely a binary file]"
            except Exception as e:
                return f"[Error reading file {os.path.basename(file_path)}: {e}]"

        if os.path.isfile(normalized_path):
            content = read_file_content(normalized_path)
            files_to_load.append((normalized_path, content))

        elif os.path.isdir(normalized_path):
            for root, dirs, filenames in os.walk(normalized_path):
                # Filter out hidden directories from further traversal
                dirs[:] = [d for d in dirs if not d.startswith(".")]

                for filename in filenames:
                    if filename.startswith("."):  # Skip hidden files
                        continue

                    full_path = os.path.join(root, filename)
                    if os.path.isfile(
                        full_path
                    ):  # Ensure it's a file (os.walk can list other things)
                        content = read_file_content(full_path)
                        files_to_load.append((full_path, content))
        else:
            raise ValueError(
                f"Path must be a valid file or a directory: {normalized_path}"
            )

        if not files_to_load and (
            os.path.isfile(normalized_path) or os.path.isdir(normalized_path)
        ):
            # This might occur if a directory is empty or contains only hidden files.
            print(
                f"Info: No non-hidden files were loaded from '{normalized_path}'."
            )

        return files_to_load


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
        Returns the RAW TEXT OUTPUT from pip-audit (NO --json FLAG USED).
        The LLM agent is expected to parse this text.
        Uses 'sys.executable -m pip_audit'.
        This version has no internal print statements.
        """
        resolved_project_path = os.path.abspath(project_path)

        base_command = [sys.executable, "-m", "pip_audit", "--progress-spinner", "off"]
        final_command_list = []
        source_description = "" 
        cwd_for_audit = resolved_project_path

        req_txt_path = os.path.join(resolved_project_path, "requirements.txt")
        req_lock_path = os.path.join(resolved_project_path, "uv.lock")
        target_req_file_for_r_flag = None

        if os.path.exists(req_lock_path):
            target_req_file_for_r_flag = req_lock_path
        elif os.path.exists(req_txt_path):
            target_req_file_for_r_flag = req_txt_path

        if target_req_file_for_r_flag:
            source_description = f"Audit of {os.path.basename(target_req_file_for_r_flag)}"
            final_command_list = base_command + ["--no-deps", "--disable-pip", "-r", target_req_file_for_r_flag]
        else:
            can_auto_detect = any(os.path.exists(os.path.join(resolved_project_path, f))
                                  for f in ["pyproject.toml", "poetry.lock", "pdm.lock"])
            if can_auto_detect:
                source_description = f"Project Directory Scan based on {project_path}"
                final_command_list = base_command 
            else:
                status_msg = "No common dependency files (requirements.txt/lock, pyproject.toml, poetry.lock, pdm.lock) found to audit."
                return json.dumps({"status": status_msg, "source_checked": project_path})

        final_command_used_str = " ".join(final_command_list)

        try:
            process = subprocess.run(
                final_command_list,
                capture_output=True,
                text=True, 
                cwd=cwd_for_audit,
                check=False 
            )
            raw_stdout = process.stdout 
            raw_stderr = process.stderr.strip()
            return_code = process.returncode

            result_payload = {
                "source_audited": source_description,
                "command_used": final_command_used_str,
                "return_code": return_code,
                "stdout": raw_stdout, 
                "stderr": raw_stderr if raw_stderr else "N/A"
            }

            if return_code != 0:
                result_payload["status_message"] = "pip-audit completed with a non-zero exit code. This may indicate vulnerabilities found or an error."
            else:
                if "No known vulnerabilities found" in raw_stdout: # Quick check for common success message
                     result_payload["status_message"] = "pip-audit completed successfully. No known vulnerabilities found."
                else:
                     result_payload["status_message"] = "pip-audit completed successfully. Review stdout for vulnerability details."

        except FileNotFoundError:
            # Construct the error payload without relying on final_command_used_str if it wasn't set
            # (though with current logic, it should always be set if this point is reached after file checks)
            cmd_attempt_info = f"{sys.executable} -m pip_audit ..." # Generic command
            if final_command_list: # If command was actually constructed
                cmd_attempt_info = " ".join(final_command_list)

            return json.dumps({
                "error": f"Failed to execute pip-audit. '{sys.executable} -m pip_audit' not found or pip_audit module missing in this environment: {sys.prefix}",
                "source_checked": source_description if source_description else project_path,
                "command_attempted_structure": cmd_attempt_info
            })
        except Exception as e:
            # Ensure final_command_used_str is defined or provide a default
            cmd_str_for_error = "N/A"
            if 'final_command_used_str' in locals() and final_command_used_str:
                cmd_str_for_error = final_command_used_str
            elif final_command_list: # If list was formed but not joined
                cmd_str_for_error = " ".join(final_command_list)

            return json.dumps({
                "error": f"An unexpected error occurred in check_dependencies: {e}",
                "command_attempted": cmd_str_for_error,
                "source_checked": source_description if source_description else project_path
            })

        return json.dumps(result_payload, indent=2)
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
        """Sanitize the file name for pretty and safe filesystem usage.
        Generates names like 'SecureSage-Report-your-file-name.md' (extension added later).
        """

        prefix = "SecureSage-Report-"

        # Handle special "summary" case (case-insensitive)
        if name.lower() == "summary":
            base_name_intermediate = "summary"
        else:
            processed_name = name
            while processed_name.startswith(("./", ".\\")):
                processed_name = processed_name[2:]
            while processed_name.startswith(("../", "..\\")):
                processed_name = processed_name[3:]

            # Replace directory separators with hyphens
            base_name_intermediate = processed_name.replace("/", "-").replace(
                "\\", "-"
            )

            base_name_intermediate = base_name_intermediate.split(".")[0]

        base_name_slug = base_name_intermediate.lower()
        base_name_slug = re.sub(r"[^a-z0-9\-]+", "-", base_name_slug)
        base_name_slug = re.sub(r"-+", "-", base_name_slug)
        base_name_slug = base_name_slug.strip("-")

        if not base_name_slug:
            base_name_slug = "untitled-report"

        full_sanitized_name = f"{prefix}{base_name_slug}"
        return full_sanitized_name[:250]


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


    user_input = f"Please analyze {CODE_PATH} for vulnerabilities."
    messages.append({"role": "user", "content": user_input})

    file_name = os.path.basename(CODE_PATH).replace(".py", "")

    print(f"Agent starting to analyze... {CODE_PATH}")
    while tool_call_count < max_turns:
        print(f"=============== AGENT TURN {tool_call_count} ================")
        response = client.chat.completions.create(
            model=model,
            messages=messages,
        )
        reply = response.choices[0].message.content
        messages.append({"role": "assistant", "content": reply})

        thought = parse_thinking_from_response(reply)
        if thought:
            print("\nAgent thought:")
            print(thought)

        answer = parse_answer_from_response(reply)
        if answer:
            split_and_write_answers(answer)
            print("Report written to markdown.")
            break

        tool_call = parse_tool_from_response(reply)
        if not tool_call:
            print("No tool call found. Exiting. Last response:")
            print(reply)
            break

        tool_name = tool_call["name"]
        args = tool_call["args"]

        print("\nTool call:")
        print(f"Tool: {tool_name}")
        print(f"Args: {json.dumps(args, indent=2)}")

        tool_func = tool_registry.get(tool_name)
        if not tool_func:
            print(f"Unknown tool: {tool_name}")
            break

        try:
            result = tool_func(**args)
        except Exception as e:
            result = {"error": str(e)}

        print("\nTool result:")
        print(json.dumps(result, indent=2))

        messages.append({"role": "user", "content": json.dumps(result, indent=2)})
        tool_call_count += 1
    return


@app.cell
def _():
    return


if __name__ == "__main__":
    app.run()
