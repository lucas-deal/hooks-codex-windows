import ctypes
import json
import re
import sys


# =============================================================================
# CONFIGURAÇÃO
# =============================================================================

# Arquivos .env que PODEM ser lidos.
# São arquivos de exemplo e não deveriam conter secrets reais.
ALLOWED_ENV_SUFFIXES = (
    ".env.example",
    ".env.sample",
    ".env.template",
)


# Mensagens exibidas pelo Codex quando uma operação é bloqueada.
SECRET_BLOCK_MESSAGE = (
    "BLOCKED: access to secrets, credentials or environment variables "
    "is not allowed. Use template/example files instead."
)

PATCH_DELETE_BLOCK_MESSAGE = (
    "BLOCKED: deleting files through apply_patch is not allowed. "
    "Use a shell deletion command so the operation can require "
    "explicit user approval."
)

DESTRUCTIVE_BLOCK_MESSAGE = (
    "BLOCKED: destructive operation was rejected by the user."
)

DESTRUCTIVE_ERROR_MESSAGE = (
    "BLOCKED: destructive operation could not obtain human confirmation."
)

WINDOW_TITLE = "Codex - confirmação de operação destrutiva"


# =============================================================================
# PADRÕES DE SECRETS
# =============================================================================

# Arquivos/pastas que normalmente armazenam credenciais.
SECRET_FILE_PATTERNS = (
    # .env
    re.compile(
        r"(^|[/\\])\.env(?:\.[A-Za-z0-9_.-]+)?$",
        re.IGNORECASE,
    ),

    # Private keys
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),

    # SSH
    re.compile(r"(^|[/\\])id_rsa$", re.IGNORECASE),
    re.compile(r"(^|[/\\])id_ed25519$", re.IGNORECASE),
    re.compile(r"(^|[/\\])\.ssh([/\\]|$)", re.IGNORECASE),

    # AWS
    re.compile(
        r"(^|[/\\])\.aws[/\\]credentials$",
        re.IGNORECASE,
    ),

    # Outros arquivos de credenciais comuns
    re.compile(r"(^|[/\\])\.netrc$", re.IGNORECASE),
    re.compile(r"(^|[/\\])\.npmrc$", re.IGNORECASE),
    re.compile(r"(^|[/\\])\.pypirc$", re.IGNORECASE),
    re.compile(r"(^|[/\\])credentials\.json$", re.IGNORECASE),

    # Codex
    re.compile(
        r"(^|[/\\])\.codex[/\\]auth\.json$",
        re.IGNORECASE,
    ),

    # Docker
    re.compile(
        r"(^|[/\\])\.docker[/\\]config\.json$",
        re.IGNORECASE,
    ),
)


# Padrões encontrados dentro de comandos de shell.
SECRET_COMMAND_PATTERNS = (
    # .env
    #
    # Exemplos bloqueados:
    # cat .env
    # Get-Content .env
    # type .env.production
    # Get-Content C:\projeto\.env.local
    #
    # .env.example / sample / template serão tratados como exceção depois.
    re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?:[A-Za-z]:)?"
        r"(?:[^ \t\r\n\"';&|<>]*[/\\])?"
        r"\.env(?:\.[A-Za-z0-9_.-]+)?"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    # Private keys
    re.compile(
        r"(?<![A-Za-z0-9_])"
        r"[^ \t\r\n\"';&|<>]*\.pem"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    re.compile(
        r"(?<![A-Za-z0-9_])"
        r"[^ \t\r\n\"';&|<>]*\.key"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    # SSH keys
    re.compile(
        r"(?<![A-Za-z0-9_])id_rsa"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    re.compile(
        r"(?<![A-Za-z0-9_])id_ed25519"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    re.compile(r"\.ssh[/\\]", re.IGNORECASE),

    # AWS credentials
    re.compile(
        r"\.aws[/\\]credentials",
        re.IGNORECASE,
    ),

    # Codex auth
    re.compile(
        r"\.codex[/\\]auth\.json",
        re.IGNORECASE,
    ),

    # Docker credentials
    re.compile(
        r"\.docker[/\\]config\.json",
        re.IGNORECASE,
    ),

    # Outros
    re.compile(
        r"(?<![A-Za-z0-9_])\.npmrc"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    re.compile(
        r"(?<![A-Za-z0-9_])\.pypirc"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    re.compile(
        r"(?<![A-Za-z0-9_])\.netrc"
        r"(?=$|[\s\"';&|<>])",
        re.IGNORECASE,
    ),

    re.compile(
        r"credentials\.json",
        re.IGNORECASE,
    ),
)


# Tentativas de listar ou acessar variáveis de ambiente.
ENVIRONMENT_PATTERNS = (
    # Linux/macOS
    re.compile(r"\bprintenv\b", re.IGNORECASE),

    # "env" sozinho ou usado para despejar variáveis
    re.compile(
        r"(^|[;&|]\s*)env\s*($|[|>])",
        re.IGNORECASE | re.MULTILINE,
    ),

    # Python
    re.compile(r"\bos\.environ\b", re.IGNORECASE),

    # Node.js
    re.compile(r"\bprocess\.env\b", re.IGNORECASE),

    # PowerShell: listar todas
    re.compile(
        r"\bGet-ChildItem\s+(?:-Path\s+)?Env:",
        re.IGNORECASE,
    ),

    re.compile(
        r"\bGet-Item\s+(?:-Path\s+)?Env:",
        re.IGNORECASE,
    ),

    re.compile(
        r"\bgci\s+Env:",
        re.IGNORECASE,
    ),

    re.compile(
        r"\bdir\s+Env:",
        re.IGNORECASE,
    ),

    re.compile(
        r"\[Environment\]::GetEnvironmentVariables",
        re.IGNORECASE,
    ),

    # PowerShell: variável específica
    #
    # Exemplos:
    # $env:OPENAI_API_KEY
    # $Env:DATABASE_PASSWORD
    re.compile(
        r"\$env:[A-Za-z_][A-Za-z0-9_]*",
        re.IGNORECASE,
    ),

    # CMD "set" sozinho lista todas as variáveis
    re.compile(
        r"^\s*set\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),

    # Bash: variáveis obviamente sensíveis
    #
    # echo $API_KEY
    # echo ${OPENAI_API_KEY}
    re.compile(
        r"\$(?:\{)?"
        r"[A-Za-z0-9_]*"
        r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)"
        r"[A-Za-z0-9_]*"
        r"(?:\})?",
        re.IGNORECASE,
    ),
)

DESTRUCTIVE_COMMAND_PATTERNS = (
    re.compile(r"\bRemove-Item\b", re.IGNORECASE),
    re.compile(r"\brm\b", re.IGNORECASE),
    re.compile(r"\brmdir\b", re.IGNORECASE),
    re.compile(r"\bdel\b", re.IGNORECASE),
    re.compile(r"\berase\b", re.IGNORECASE),
    re.compile(r"\bunlink\b", re.IGNORECASE),

    # PowerShell aliases
    re.compile(r"\bri\b", re.IGNORECASE),
    re.compile(r"\brd\b", re.IGNORECASE),

    # Git
    re.compile(
        r"\bgit\s+clean\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bgit\s+reset\s+--hard\b",
        re.IGNORECASE,
    ),

    # Python
    re.compile(
        r"\bos\.(?:remove|unlink|rmdir)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bshutil\.rmtree\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\.unlink\s*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\.rmdir\s*\(",
        re.IGNORECASE,
    ),

    # PowerShell / .NET - exclusão de arquivos
    re.compile(
        r"\[(?:System\.)?IO\.File\]\s*::\s*Delete\s*\(",
        re.IGNORECASE,
    ),

    # PowerShell / .NET - exclusão de diretórios
    re.compile(
        r"\[(?:System\.)?IO\.Directory\]\s*::\s*Delete\s*\(",
        re.IGNORECASE,
    ),

    # Node.js - fs.unlink / fs.rm / fs.rmdir
    re.compile(
        r"(?:"
        r"\bfs"
        r"|"
        r"require\s*\(\s*['\"](?:node:)?fs['\"]\s*\)"
        r")"
        r"(?:\.promises)?"
        r"\s*\.\s*"
        r"(?:unlinkSync|unlink|rmSync|rm|rmdirSync|rmdir)"
        r"\s*\(",
        re.IGNORECASE,
    ),

    # PowerShell / .NET - FileInfo.Delete()
    re.compile(
        r"(?:New-Object\s+System\.IO\.FileInfo|"
        r"\[System\.IO\.FileInfo\]\s*::\s*new|"
        r"\[IO\.FileInfo\]\s*::\s*new)"
        r".*?\.Delete\s*\(",
        re.IGNORECASE,
    ),

    # PowerShell / .NET - DirectoryInfo.Delete()
    re.compile(
        r"(?:New-Object\s+System\.IO\.DirectoryInfo|"
        r"\[System\.IO\.DirectoryInfo\]\s*::\s*new|"
        r"\[IO\.DirectoryInfo\]\s*::\s*new)"
        r".*?\.Delete\s*\(",
        re.IGNORECASE,
    ),
)


# =============================================================================
# FUNÇÕES AUXILIARES
# =============================================================================

def normalize_path(value: str) -> str:
    """
    Normaliza barras para facilitar comparações.
    """
    return value.replace("\\", "/")


def normalize_command(command: str) -> str:
    """
    Cria uma segunda versão simplificada do comando.

    Não é um parser completo de PowerShell/Bash/CMD.
    Serve apenas para reduzir variações triviais de espaços e aspas.
    """
    return " ".join(command.split())


def is_allowed_env_file(value: str) -> bool:
    """
    Retorna True para arquivos .env que são templates permitidos.
    """
    normalized = normalize_path(value).lower().strip(
        " \t\r\n\"';&|<>"
    )

    return any(
        normalized.endswith(suffix)
        for suffix in ALLOWED_ENV_SUFFIXES
    )


def remove_allowed_env_templates(command: str) -> str:
    """
    Remove do texto referências aos .env permitidos.

    Isso permite, por exemplo:

        Get-Content .env.example

    sem disparar o detector genérico de .env.
    """

    result = command

    for suffix in ALLOWED_ENV_SUFFIXES:
        result = re.sub(
            re.escape(suffix),
            "",
            result,
            flags=re.IGNORECASE,
        )

    return result


# =============================================================================
# DETECÇÃO DE ARQUIVOS SECRETOS
# =============================================================================

def contains_secret_file_path(value: str) -> bool:
    """
    Detecta se um caminho isolado aponta para um arquivo secreto.
    """

    if not value:
        return False

    normalized = normalize_path(value).strip(
        " \t\r\n\"'"
    )

    if is_allowed_env_file(normalized):
        return False

    for pattern in SECRET_FILE_PATTERNS:
        if pattern.search(normalized):
            return True

    return False


def contains_secret_in_command(command: str) -> bool:
    """
    Detecta referências a arquivos secretos dentro de comandos shell.
    """

    if not command:
        return False

    # Remove .env.example / sample / template antes da análise.
    sanitized = remove_allowed_env_templates(command)

    for pattern in SECRET_COMMAND_PATTERNS:
        if pattern.search(sanitized):
            return True

    return False


def contains_environment_access(command: str) -> bool:
    """
    Detecta tentativas de inspecionar variáveis de ambiente.
    """

    if not command:
        return False

    return any(
        pattern.search(command)
        for pattern in ENVIRONMENT_PATTERNS
    )


# =============================================================================
# DETECÇÃO DE ACESSO A SECRETS
# =============================================================================

def is_secret_access(tool_name: str, tool_input: dict) -> bool:
    """
    Detecta tentativas de acessar:
      - .env
      - private keys
      - credenciais
      - variáveis de ambiente

    Suporta nomes de tools usados pelo Claude e pelo Codex.
    """

    name = tool_name.lower().strip()

    # -------------------------------------------------------------------------
    # Ferramentas de arquivo
    # -------------------------------------------------------------------------

    file_tools = {
        "read",
        "read_file",
        "read_text_file",
        "write",
        "edit",
        "multiedit",
        "notebookedit",
    }

    if name in file_tools:
        possible_path_fields = (
            "file_path",
            "path",
            "filename",
        )

        for key in possible_path_fields:
            value = tool_input.get(key)

            if value and contains_secret_file_path(str(value)):
                return True

    # -------------------------------------------------------------------------
    # Ferramentas de busca
    # -------------------------------------------------------------------------

    search_tools = {
        "grep",
        "glob",
        "search",
    }

    if name in search_tools:
        values = []

        for key in (
            "pattern",
            "path",
            "query",
            "include",
        ):
            value = tool_input.get(key)

            if value:
                values.append(str(value))

        combined = " ".join(values)

        if contains_secret_in_command(combined):
            return True

    # -------------------------------------------------------------------------
    # Shell
    # -------------------------------------------------------------------------

    shell_tools = {
        "bash",
        "powershell",
        "shell",
        "shell_command",
        "exec_command",
        "command_execution",
    }

    if name in shell_tools:
        raw_command = str(
            tool_input.get("command", "")
        )

        commands_to_check = (
            raw_command,
            normalize_command(raw_command),
        )

        for command in commands_to_check:

            if contains_secret_in_command(command):
                return True

            if contains_environment_access(command):
                return True

    return False


# =============================================================================
# DETECÇÃO DE DELETE VIA APPLY_PATCH
# =============================================================================

def is_apply_patch_delete(tool_name: str, tool_input: dict) -> bool:
    """
    Impede que o Codex use apply_patch para apagar arquivos.

    Exemplo bloqueado:

        *** Begin Patch
        *** Delete File: arquivo.txt
        *** End Patch

    A ideia é obrigar exclusões a passarem pelo shell,
    onde você pode aplicar uma regra de aprovação.
    """

    name = tool_name.lower().strip()

    if name != "apply_patch":
        return False

    # Dependendo da implementação, o patch pode aparecer
    # em command ou patch.
    patch = str(
        tool_input.get(
            "command",
            tool_input.get("patch", ""),
        )
    )

    return bool(
        re.search(
            r"^\s*\*\*\*\s+Delete\s+File\s*:",
            patch,
            re.IGNORECASE | re.MULTILINE,
        )
    )


# =============================================================================
# RESPOSTA PARA O CODEX
# =============================================================================

def deny(reason: str) -> None:
    """
    Retorna uma decisão explícita de DENY ao Codex.
    """

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }

    print(json.dumps(output))
    sys.exit(0)


# =============================================================================
# FUNÇÃO AUXILIAR AÇÕES DESTRUTIVAS
# =============================================================================

def is_destructive_command(command: str) -> bool:
    if not command:
        return False

    return any(
        pattern.search(command)
        for pattern in DESTRUCTIVE_COMMAND_PATTERNS
    )


def ask_human_for_destructive_command(
    command: str,
    cwd: str,
) -> bool:
    if sys.platform != "win32":
        return False

    MB_YESNO = 0x00000004
    MB_ICONWARNING = 0x00000030
    MB_SETFOREGROUND = 0x00010000
    MB_TOPMOST = 0x00040000

    IDYES = 6

    displayed_command = command

    if len(displayed_command) > 1800:
        displayed_command = (
            displayed_command[:1800]
            + "\n\n[command truncated]"
        )

    message = (
        "O Codex quer executar uma operação destrutiva.\n\n"
        "Diretório:\n"
        f"{cwd}\n\n"
        "Comando:\n"
        f"{displayed_command}\n\n"
        "Deseja permitir esta operação?"
    )

    result = ctypes.windll.user32.MessageBoxW(
        None,
        message,
        WINDOW_TITLE,
        MB_YESNO
        | MB_ICONWARNING
        | MB_SETFOREGROUND
        | MB_TOPMOST,
    )

    return result == IDYES


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:

    try:
        data = json.load(sys.stdin)

        tool_name = str(
            data.get("tool_name", "")
        )

        tool_input = data.get(
            "tool_input",
            {},
        )

        if not isinstance(tool_input, dict):
            tool_input = {}

        # ---------------------------------------------------------------------
        # Bloqueia secrets
        # ---------------------------------------------------------------------

        if is_secret_access(
            tool_name,
            tool_input,
        ):
            deny(SECRET_BLOCK_MESSAGE)

        # ---------------------------------------------------------------------
        # Confirmação humana para operações destrutivas via shell
        # ---------------------------------------------------------------------

        shell_tools = {
            "bash",
            "powershell",
            "shell",
            "shell_command",
            "exec_command",
            "command_execution",
        }

        if tool_name.lower().strip() in shell_tools:
            command = str(
                tool_input.get("command", "")
            )

            if is_destructive_command(command):
                cwd = str(
                    data.get("cwd", "")
                )

                if not ask_human_for_destructive_command(
                    command,
                    cwd,
                ):
                    deny(DESTRUCTIVE_BLOCK_MESSAGE)

        # ---------------------------------------------------------------------
        # Bloqueia delete via apply_patch
        # ---------------------------------------------------------------------

        if is_apply_patch_delete(
            tool_name,
            tool_input,
        ):
            deny(PATCH_DELETE_BLOCK_MESSAGE)

        # ---------------------------------------------------------------------
        # Nenhum problema encontrado
        # ---------------------------------------------------------------------

        # Sem stdout = operação liberada.
        sys.exit(0)

    except Exception as exc:
        print(
            "BLOCKED: security hook failed internally: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
    sys.exit(2)


if __name__ == "__main__":
    main()