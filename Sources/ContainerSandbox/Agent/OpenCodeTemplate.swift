struct OpenCodeTemplate: AgentTemplate {
    let name = "opencode"
    let defaultImage = "container-sandbox-opencode:latest"

    let entrypoint = ["/home/sandbox/.opencode/bin/opencode"]

    let defaultEnvironment: [String: String] = [
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    /// OpenCode is provider-agnostic; pass through the common provider keys.
    let passthroughEnvironment = [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
    ]

    let requiresSSH = true
    let requiresVirtualization = false
    let useInit = true

    /// Install script drops the binary at ~/.opencode/bin/opencode and edits
    /// shell rc files we don't use. Wildcard-allow permissions match the
    /// intent of Claude's --dangerously-skip-permissions: this VM is the
    /// hardened boundary, not the agent's prompt.
    let containerfileContent: String? =
        SandboxBaseImage.containerfileContent + ##"""


            RUN curl -fsSL https://opencode.ai/install | bash -s -- --no-modify-path \
                && test -x /home/sandbox/.opencode/bin/opencode

            RUN mkdir -p /home/sandbox/.config/opencode && printf '%s\n' \
                '{' \
                '  "$schema": "https://opencode.ai/config.json",' \
                '  "permission": {' \
                '    "*": "allow"' \
                '  }' \
                '}' > /home/sandbox/.config/opencode/opencode.json
            """##
}
