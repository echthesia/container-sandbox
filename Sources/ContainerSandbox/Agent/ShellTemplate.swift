struct ShellTemplate: AgentTemplate {
    let name = "shell"

    let entrypoint = ["/bin/bash"]

    let defaultEnvironment: [String: String] = [
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    let passthroughEnvironment: [String] = []

    let requiresSSH = true
    let requiresVirtualization = false
    let useInit = true

    let containerfileContent: String? = SandboxBaseImage.containerfileContent
}
