struct ShellTemplate: AgentTemplate {
    let name = "shell"
    let defaultImage = "docker.io/ubuntu:24.04"

    let entrypoint = ["/bin/bash"]

    let defaultEnvironment: [String: String] = [:]

    let passthroughEnvironment: [String] = []

    let requiresSSH = false
    let requiresVirtualization = false
    let useInit = true
}
