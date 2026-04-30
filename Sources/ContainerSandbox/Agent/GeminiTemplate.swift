struct GeminiTemplate: AgentTemplate {
    let name = "gemini"

    let entrypoint = ["/home/sandbox/.local/bin/gemini", "--yolo"]

    let defaultEnvironment: [String: String] = [
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
    ]

    let passthroughEnvironment = [
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ]

    let requiresSSH = true
    let requiresVirtualization = false
    let useInit = true

    let containerfileContent: String? =
        SandboxBaseImage.containerfileContent + ##"""


            RUN npm install -g @google/gemini-cli \
                && test -x /home/sandbox/.local/bin/gemini
            """##
}
