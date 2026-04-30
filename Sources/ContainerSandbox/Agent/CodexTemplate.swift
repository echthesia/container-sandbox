struct CodexTemplate: AgentTemplate {
    let name = "codex"

    /// The bypass flag is meant for use inside an externally hardened
    /// sandbox (per OpenAI docs) — that's exactly what we are.
    let entrypoint = [
        "/home/sandbox/.local/bin/codex",
        "--dangerously-bypass-approvals-and-sandbox",
    ]

    let defaultEnvironment: [String: String] = [
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    let passthroughEnvironment = [
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_ORG_ID",
    ]

    let requiresSSH = true
    let requiresVirtualization = false
    let useInit = true

    let containerfileContent: String? =
        SandboxBaseImage.containerfileContent + ##"""


            RUN npm install -g @openai/codex \
                && test -x /home/sandbox/.local/bin/codex
            """##
}
