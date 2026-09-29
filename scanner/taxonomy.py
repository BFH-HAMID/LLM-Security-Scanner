"""OWASP LLM Top 10 (2025) and MITRE ATLAS mappings plus default remediation guidance.

Technique / mitigation identifiers were checked against the MITRE ATLAS data release
``2026.09`` (https://github.com/mitre-atlas/atlas-data) and the OWASP Top 10 for LLM
Applications 2025 (https://genai.owasp.org/llm-top-10/).

Note on naming: the 2023 list called LLM05 "Insecure Output Handling" and LLM06 "Sensitive
Information Disclosure"; the 2025 edition used here renumbers/renames them. This project
uses 2025 identifiers everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.models import Category

OWASP_EDITION = "2025"

OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

ATLAS_VERSION = "2026.09"

ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0048": "External Harms",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0051.002": "LLM Prompt Injection: Triggered",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0065": "LLM Prompt Crafting",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0069": "Discover LLM System Information",
    "AML.T0069.001": "Discover LLM System Information: System Instruction Keywords",
    "AML.T0069.002": "Discover LLM System Information: System Prompt",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0080.000": "AI Agent Context Poisoning: Memory",
    "AML.T0082": "RAG Credential Harvesting",
    "AML.T0084.001": "Discover AI Agent Configuration: Tool Definitions",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0093": "Prompt Infiltration via Public-Facing Application",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
}

ATLAS_MITIGATIONS: dict[str, str] = {
    "AML.M0019": "Control Access to AI Models and Data in Production",
    "AML.M0020": "Generative AI Guardrails",
    "AML.M0021": "Generative AI Guidelines",
    "AML.M0022": "Generative AI Model Alignment",
    "AML.M0026": "Privileged AI Agent Permissions Configuration",
    "AML.M0028": "AI Agent Tools Permissions Configuration",
    "AML.M0029": "Human In-the-Loop for AI Agent Actions",
    "AML.M0030": "Restrict AI Agent Tool Invocation on Untrusted Data",
    "AML.M0033": "Input and Output Validation for AI Agent Components",
    "AML.M0037": "AI Agent Authority Expansion Controls",
}


def owasp_url(owasp_id: str) -> str:
    slug = {
        "LLM01": "llm01-prompt-injection",
        "LLM02": "llm022025-sensitive-information-disclosure",
        "LLM05": "llm052025-improper-output-handling",
        "LLM06": "llm062025-excessive-agency",
        "LLM07": "llm072025-system-prompt-leakage",
        "LLM08": "llm082025-vector-and-embedding-weaknesses",
    }.get(owasp_id)
    base = "https://genai.owasp.org/llmrisk/"
    return f"{base}{slug}/" if slug else "https://genai.owasp.org/llm-top-10/"


def atlas_url(technique_id: str) -> str:
    return f"https://atlas.mitre.org/techniques/{technique_id}"


def describe_owasp(owasp_id: str) -> str:
    return f"{owasp_id}:{OWASP_EDITION} {OWASP_LLM_TOP10.get(owasp_id, 'Unknown')}"


def describe_atlas(technique_id: str) -> str:
    return f"{technique_id} {ATLAS_TECHNIQUES.get(technique_id, 'Unknown')}"


# ------------------------------------------------------------------- categories


@dataclass(frozen=True)
class Remediation:
    summary: str
    steps: tuple[str, ...]
    mitigations: tuple[str, ...] = ()  # ATLAS mitigation ids

    def as_text(self) -> str:
        lines = [self.summary, ""]
        lines += [f"- {s}" for s in self.steps]
        if self.mitigations:
            names = ", ".join(
                f"{m} {ATLAS_MITIGATIONS.get(m, '')}".strip() for m in self.mitigations
            )
            lines += ["", f"Related MITRE ATLAS mitigations: {names}."]
        return "\n".join(lines).strip()


@dataclass(frozen=True)
class CategoryInfo:
    key: Category
    title: str
    description: str
    owasp: tuple[str, ...]
    atlas: tuple[str, ...]
    remediation: Remediation


CATEGORIES: dict[Category, CategoryInfo] = {
    Category.PROMPT_INJECTION: CategoryInfo(
        key=Category.PROMPT_INJECTION,
        title="Direct prompt injection",
        description=(
            "User-supplied text overrides or rewrites the application's instructions "
            "(instruction override, delimiter/role spoofing, encoded or obfuscated payloads)."
        ),
        owasp=("LLM01",),
        atlas=("AML.T0051.000",),
        remediation=Remediation(
            summary=(
                "The model followed attacker instructions that contradict the application's "
                "instructions. Prompt-only rules are not a security boundary."
            ),
            steps=(
                "Treat every user message as untrusted. Enforce authorisation and business rules in "
                "code outside the model; never rely on 'do not ...' lines in the system prompt.",
                "Keep instructions and data in separate roles/fields and prefer providers' "
                "instruction-hierarchy features; do not concatenate user text into the system prompt.",
                "Normalise input before filtering (Unicode NFKC, strip zero-width characters, decode "
                "common encodings such as base64/hex/ROT13). Filters that only inspect raw text are "
                "bypassed by trivial obfuscation.",
                "Add layered guardrails: an injection classifier on inputs and a policy check on "
                "outputs, evaluated on the whole conversation, not only the last turn.",
                "Keep secrets and privileged data out of the model context; give the model the "
                "minimum data needed for the current user only.",
                "Add these probes to CI and track the attack success rate per release.",
            ),
            mitigations=("AML.M0020", "AML.M0021", "AML.M0022"),
        ),
    ),
    Category.INDIRECT_INJECTION: CategoryInfo(
        key=Category.INDIRECT_INJECTION,
        title="Indirect prompt injection",
        description=(
            "Instructions hidden in content the model processes on the user's behalf — emails, web "
            "pages, uploaded documents, RAG chunks — are executed as if they came from the user."
        ),
        owasp=("LLM01", "LLM08"),
        atlas=("AML.T0051.001", "AML.T0070", "AML.T0071"),
        remediation=Remediation(
            summary=(
                "The model obeyed instructions embedded in untrusted third-party content "
                "(retrieved documents, emails, web pages)."
            ),
            steps=(
                "Mark retrieved and uploaded content as untrusted data: wrap it in clear delimiters "
                "and instruct the model never to follow instructions found inside it (defence in "
                "depth — not sufficient on its own).",
                "Sanitise at ingestion time: strip HTML comments, hidden/zero-size CSS text, "
                "zero-width and control characters, alt-text and metadata fields; scan documents with "
                "an injection classifier before indexing.",
                "Never let untrusted content trigger tools. Require explicit user confirmation for "
                "any side-effecting action that follows retrieval of external content.",
                "Close exfiltration channels: do not render external images/links produced by the "
                "model, or restrict them to an allow-list of domains.",
                "Track provenance and trust level per chunk and log which documents influenced an "
                "answer so poisoned sources can be found and removed.",
            ),
            mitigations=("AML.M0020", "AML.M0030", "AML.M0033"),
        ),
    ),
    Category.JAILBREAK: CategoryInfo(
        key=Category.JAILBREAK,
        title="Jailbreaks",
        description=(
            "Role-play personas, encoding tricks, hypothetical framing, refusal suppression, "
            "multi-turn escalation and many-shot pressure that make the model abandon its policy."
        ),
        owasp=("LLM01",),
        atlas=("AML.T0054", "AML.T0068"),
        remediation=Remediation(
            summary="The model abandoned its behavioural policy under a jailbreak technique.",
            steps=(
                "Apply moderation on both input and output with a model that is separate from the "
                "one being protected, and evaluate multi-turn context (crescendo attacks look "
                "harmless one message at a time).",
                "Do not accept client-supplied assistant/system turns. Rebuild conversation history "
                "server-side so attackers cannot fabricate a compliant transcript (many-shot).",
                "Cap conversation length and context size exposed to untrusted users.",
                "Choose a model with strong safety alignment for user-facing use and re-test after "
                "every model or system-prompt change.",
                "Rate-limit and monitor for repeated policy-violating attempts per user.",
            ),
            mitigations=("AML.M0020", "AML.M0021", "AML.M0022"),
        ),
    ),
    Category.SYSTEM_PROMPT_EXTRACTION: CategoryInfo(
        key=Category.SYSTEM_PROMPT_EXTRACTION,
        title="System prompt extraction",
        description=(
            "The model reveals its hidden instructions, configuration, tool definitions or "
            "embedded secrets when asked directly or through transformation tricks."
        ),
        owasp=("LLM07",),
        atlas=("AML.T0056", "AML.T0069.002"),
        remediation=Remediation(
            summary="The system prompt (or parts of it) can be extracted by an attacker.",
            steps=(
                "Assume the system prompt is public. Remove credentials, API keys, internal URLs and "
                "security-relevant business rules from it.",
                "Move authorisation, limits and routing logic to application code where users cannot "
                "talk it out of enforcement.",
                "Add an output filter that blocks verbatim or near-verbatim prompt fragments and "
                "plant canary tokens in the prompt to detect leaks in production.",
                "Refuse transformation requests (translate/summarise/encode 'your instructions') the "
                "same way as direct requests.",
            ),
            mitigations=("AML.M0020", "AML.M0021"),
        ),
    ),
    Category.SENSITIVE_DATA_LEAKAGE: CategoryInfo(
        key=Category.SENSITIVE_DATA_LEAKAGE,
        title="Sensitive data leakage",
        description=(
            "PII, credentials, internal documents or other users' data appear in responses "
            "(context leakage, RAG over-retrieval, cross-session bleed, secret disclosure)."
        ),
        owasp=("LLM02", "LLM08"),
        atlas=("AML.T0057", "AML.T0024", "AML.T0082"),
        remediation=Remediation(
            summary="Sensitive data reachable by the model was disclosed to an unauthorised user.",
            steps=(
                "Enforce per-user authorisation at retrieval time (metadata filters in the vector "
                "store / row-level security), not in the prompt. If the model can read it, assume the "
                "user can extract it.",
                "Minimise what enters the context window: redact or tokenise PII and secrets before "
                "they reach the model.",
                "Add output DLP: scan responses for PII and credential patterns and redact or block.",
                "Isolate sessions and tenants; never reuse conversation memory across users.",
                "Store secrets in a secret manager and call APIs from code, not from model context.",
            ),
            mitigations=("AML.M0019", "AML.M0020", "AML.M0033"),
        ),
    ),
    Category.INSECURE_OUTPUT_HANDLING: CategoryInfo(
        key=Category.INSECURE_OUTPUT_HANDLING,
        title="Insecure output handling",
        description=(
            "Model output that carries active content (XSS, SQL, shell, template or CSV injection, "
            "exfiltrating markdown images) which downstream components may execute or render."
        ),
        owasp=("LLM05",),
        atlas=("AML.T0077", "AML.T0067"),
        remediation=Remediation(
            summary=(
                "The model emitted raw active content. If your client, database or shell consumes it "
                "unencoded this becomes XSS / injection."
            ),
            steps=(
                "Treat model output exactly like untrusted user input: apply context-aware output "
                "encoding (HTML-escape, URL-encode, SQL parameters).",
                "Render markdown with a sanitiser (e.g. DOMPurify) and a strict Content-Security-"
                "Policy; block or proxy external images and links produced by the model.",
                "Never pass model output to eval/exec/shell or string-built SQL. Use parameterised "
                "queries and schema-validated tool arguments.",
                "Escape spreadsheet formula prefixes (=, +, -, @) when exporting model output to CSV/XLSX.",
            ),
            mitigations=("AML.M0033", "AML.M0020"),
        ),
    ),
    Category.EXCESSIVE_AGENCY: CategoryInfo(
        key=Category.EXCESSIVE_AGENCY,
        title="Excessive agency",
        description=(
            "The agent invokes tools it should not, with attacker-chosen arguments, or performs "
            "high-impact actions without authorisation or confirmation."
        ),
        owasp=("LLM06",),
        atlas=("AML.T0053", "AML.T0086", "AML.T0101"),
        remediation=Remediation(
            summary="The agent performed an unauthorised or unsafe tool action.",
            steps=(
                "Expose the minimum set of tools; remove or disable shell, arbitrary HTTP and "
                "write-anything tools that the use case does not need.",
                "Run tools with the end user's own scoped credentials (on-behalf-of), never a shared "
                "admin identity.",
                "Validate tool arguments server-side against policy (recipient/domain allow-lists, "
                "path sandboxes, SELECT-only SQL, URL allow-lists, amount limits) — do not trust the "
                "model to self-police.",
                "Require human approval for irreversible or high-impact actions and do not let "
                "content from documents, emails or web pages trigger tools.",
                "Rate-limit tool calls per session and keep an audit log of every invocation.",
            ),
            mitigations=("AML.M0026", "AML.M0028", "AML.M0029", "AML.M0030", "AML.M0037"),
        ),
    ),
}


def category_info(category: Category | str) -> CategoryInfo:
    return CATEGORIES[Category(category)]


def default_remediation(category: Category | str) -> str:
    return category_info(category).remediation.as_text()
