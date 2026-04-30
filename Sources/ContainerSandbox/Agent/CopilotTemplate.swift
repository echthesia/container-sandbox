struct CopilotTemplate: AgentTemplate {
    let name = "copilot"
    let defaultImage = "container-sandbox-copilot:latest"

    /// --yolo == --allow-all-tools + --allow-all-paths + --allow-all-urls.
    /// --allow-all-tools alone still prompts on path writes and URL fetches.
    let entrypoint = ["/home/sandbox/.local/bin/copilot", "--yolo"]

    let defaultEnvironment: [String: String] = [
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    /// Copilot CLI checks COPILOT_GITHUB_TOKEN, then GH_TOKEN, then GITHUB_TOKEN.
    let passthroughEnvironment = [
        "COPILOT_GITHUB_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ]

    let requiresSSH = true
    let requiresVirtualization = false
    let useInit = true

    let containerfileContent: String? =
        SandboxBaseImage.containerfileContent + ##"""


            RUN npm install -g @github/copilot \
                && test -x /home/sandbox/.local/bin/copilot
            """##
}
