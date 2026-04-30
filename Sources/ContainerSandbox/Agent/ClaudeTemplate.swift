struct ClaudeTemplate: AgentTemplate {
    let name = "claude"

    let entrypoint = ["/home/sandbox/.local/bin/claude", "--dangerously-skip-permissions"]

    let defaultEnvironment: [String: String] = [
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    let passthroughEnvironment = [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ]

    let requiresSSH = true
    let requiresVirtualization = false
    let useInit = true
    let defaultNetworkPolicy = NetworkPolicy.allow

    let containerfileContent: String? =
        SandboxBaseImage.containerfileContent + ##"""


            RUN curl -fsSL https://claude.ai/install.sh | bash
            """##
}
