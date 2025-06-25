from llm.llm_interface import get_llm
import json
import os

class AttackChain:
    def __init__(self, target_url, memory_path="agent/memory/agent_memory.json", prompt_path="agent/prompts/sqli_prompt.txt"):
        self.target_url = target_url
        self.memory_path = memory_path
        self.prompt_path = prompt_path
        self.llm = get_llm()
        self.memory = self.load_memory()

    def load_memory(self):
        if os.path.exists(self.memory_path):
            with open(self.memory_path, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            return {"findings": [], "decisions": [], "tools_used": [], "reports": []}

    def save_memory(self):
        with open(self.memory_path, "w", encoding="utf-8") as f:
            json.dump(self.memory, f, indent=2)

    def get_prompt(self):
        with open(self.prompt_path, "r", encoding="utf-8") as f:
            prompt_template = f.read()
        return prompt_template.replace("{target_url}", self.target_url)

    def think_and_decide(self, context):
        prompt = self.get_prompt() + "\n\nContext:\n" + context + "\n\nWhat is the next best action?"
        response = self.llm.generate(prompt)
        self.memory["decisions"].append(response)
        self.save_memory()
        return response

    def update_findings(self, finding):
        self.memory["findings"].append(finding)
        self.save_memory()

    def update_tools_used(self, tool_name):
        self.memory["tools_used"].append(tool_name)
        self.save_memory()

    def generate_report(self):
        report_md = "# Penetration Testing Report\n\n"
        report_md += f"Target: {self.target_url}\n\n"
        report_md += "## Findings\n"
        for finding in self.memory.get("findings", []):
            report_md += f"- {finding}\n"
        report_md += "\n## Tools Used\n"
        for tool in set(self.memory.get("tools_used", [])):
            report_md += f"- {tool}\n"
        report_md += "\n## Decisions\n"
        for decision in self.memory.get("decisions", []):
            report_md += f"- {decision}\n"
        self.memory["reports"].append(report_md)
        self.save_memory()
        return report_md
