struct ClaudeTemplate: AgentTemplate, Sendable {
    let name = "claude"
    let defaultImage = "docker.io/ubuntu:24.04"

    let entrypoint = ["/usr/local/bin/claude", "--dangerously-skip-permissions"]

    let defaultEnvironment: [String: String] = [
        "TERM": "xterm-256color",
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    let passthroughEnvironment = [
        "ANTHROPIC_API_KEY",
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
    let requiresVirtualization = true
    let useInit = true
}
