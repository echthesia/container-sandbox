struct ShellTemplate: AgentTemplate, Sendable {
    let name = "shell"
    let defaultImage = "docker.io/ubuntu:24.04"

    let entrypoint = ["/bin/bash"]

    let defaultEnvironment: [String: String] = [
        "TERM": "xterm-256color",
    ]

    let passthroughEnvironment: [String] = []

    let requiresSSH = false
    let requiresVirtualization = false
    let useInit = true
}
