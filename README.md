# Codex Security Hooks for Windows

Camada adicional de segurança para o **OpenAI Codex no Windows**, criada para reduzir o risco de o agente ler arquivos/variáveis sensíveis e executar deleções sem confirmação humana explícita.

> [!IMPORTANT]
> Este projeto foi desenvolvido e testado especificamente com **Codex (CLI/extensão de IDE) no Windows**. A confirmação visual de operações destrutivas usa a API nativa do Windows (`MessageBoxW`) e não foi projetada para oferecer a mesma experiência em Linux ou macOS.

## Objetivo

A configuração implementa duas proteções principais:

1. **Bloqueio de leitura/acesso a secrets** antes da execução da ferramenta.
2. **Confirmação humana obrigatória para operações destrutivas**, mesmo quando o Codex está configurado para aprovar automaticamente outras ações.

A intenção não é substituir o sandbox, as permissões ou os mecanismos nativos do Codex, mas adicionar uma camada defensiva adicional.

## Estrutura recomendada do repositório

```text
.
├── hooks/
│   ├── pre_tool_use_secrets.py
│   └── pre_tool_use_secrets.cmd
├── rules/
│   └── default.rules
├── hooks.json
├── LICENSE
└── README.md
```

### `hooks/pre_tool_use_secrets.py`

É a principal camada de segurança.

O script é executado no evento `PreToolUse`, recebe do Codex um objeto JSON via `stdin` e analisa a ferramenta que está prestes a ser executada.

Ele possui três responsabilidades principais:

* bloquear acesso a arquivos e informações sensíveis;
* bloquear exclusões feitas diretamente por `apply_patch`;
* exigir confirmação humana para comandos de shell reconhecidos como destrutivos.

### `hooks/pre_tool_use_secrets.cmd`

Wrapper para Windows responsável por iniciar o script Python.

Ele também funciona como uma camada de **fail closed**: se o Python falhar e retornar um código inesperado, o wrapper converte a falha em bloqueio em vez de permitir silenciosamente a operação.

### `hooks.json`

Registra o hook `PreToolUse` no Codex e aponta para o wrapper `.cmd` no Windows.

A configuração usa `commandWindows`, permitindo resolver o caminho a partir de `%USERPROFILE%` e evitando depender do nome do usuário da máquina.

O timeout precisa ser suficientemente alto porque, para comandos destrutivos, o hook permanece aguardando o clique humano em **Sim** ou **Não**.

### `rules/default.rules`

Adiciona regras de `execpolicy` para comandos destrutivos conhecidos, como:

* `rm`;
* `rmdir`;
* `del`;
* `erase`;
* `Remove-Item`;
* `git clean`;
* `git reset --hard`.

Essas regras são uma camada adicional de defesa.

Neste projeto, elas **não são a única barreira de segurança**. A confirmação humana efetiva de deleções é realizada no `PreToolUse`, pois modos de aprovação automática podem tornar inadequado depender apenas de uma decisão `prompt` para garantir que um humano clique em Aprovar.

## Como o fluxo funciona

### Acesso a secrets

Fluxo simplificado:

```text
Codex tenta usar uma ferramenta
        ↓
PreToolUse
        ↓
O comando/caminho contém um secret protegido?
        ↓
      Sim
        ↓
permissionDecision = deny
        ↓
A ferramenta não é executada
```

Entre os padrões protegidos estão arquivos e caminhos como:

* `.env` e variantes;
* arquivos `.pem` e `.key`;
* chaves SSH, como `id_rsa` e `id_ed25519`;
* `.ssh`;
* credenciais da AWS;
* `.netrc`;
* `.npmrc`;
* `.pypirc`;
* `credentials.json`;
* credenciais do Codex;
* configuração sensível do Docker.

Arquivos de template podem ser permitidos, por exemplo:

```text
.env.example
.env.sample
.env.template
```

O hook também procura tentativas comuns de inspecionar variáveis de ambiente, incluindo padrões de PowerShell, Bash, Python e Node.js.

### Operações destrutivas

Para comandos reconhecidos como destrutivos:

```text
Codex prepara o comando
        ↓
PreToolUse
        ↓
Comando destrutivo detectado
        ↓
Janela nativa do Windows
        ↓
   ┌───────────────┐
   │  Sim  |  Não  │
   └───────────────┘
      ↓        ↓
   continua   deny
```

Isso mantém a aprovação humana separada do modo geral de aprovação usado pelo Codex.

### Exclusão via `apply_patch`

Exclusões com patches como:

```text
*** Begin Patch
*** Delete File: arquivo.txt
*** End Patch
```

são bloqueadas diretamente.

A ideia é impedir que o agente contorne a confirmação humana apagando um arquivo através de `apply_patch`. Para excluir um arquivo, o agente precisa recorrer a uma operação de shell coberta pela política de confirmação.

## Operações destrutivas cobertas

A implementação atual foi testada contra formas comuns de exclusão no Windows e por interpretadores frequentemente usados pelo Codex.

### Shell / PowerShell / CMD

```text
Remove-Item
rm
rmdir
del
erase
unlink
ri
rd
cmd /c del
powershell -Command Remove-Item
```

### Git

```text
git clean
git reset --hard
```

### Python

Exemplos detectados incluem:

```python
os.remove(...)
os.unlink(...)
os.rmdir(...)
shutil.rmtree(...)
Path(...).unlink()
Path(...).rmdir()
```

### PowerShell / .NET

Exemplos detectados incluem:

```powershell
[System.IO.File]::Delete(...)
[IO.File]::Delete(...)
[System.IO.Directory]::Delete(...)
[IO.Directory]::Delete(...)
[System.IO.FileInfo]::new(...).Delete()
[System.IO.DirectoryInfo]::new(...).Delete()
```

### Node.js

Exemplos detectados incluem APIs como:

```javascript
fs.unlinkSync(...)
fs.unlink(...)
fs.rmSync(...)
fs.rm(...)
fs.rmdirSync(...)
fs.rmdir(...)
fs.promises.unlink(...)
fs.promises.rm(...)
```

## Requisitos

* Windows;
* OpenAI Codex com suporte a hooks;
* Python 3;
* Python Launcher for Windows (`py`) disponível no `PATH`;
* PowerShell para os comandos de instalação/teste abaixo.

Confirme o Python:

```powershell
py -3 --version
```

## Instalação em outro computador

### 1. Clone ou baixe este repositório

Abra um PowerShell na raiz do repositório.

### 2. Crie as pastas do Codex

```powershell
$codexDir = "$env:USERPROFILE\.codex"

New-Item -ItemType Directory -Force "$codexDir\hooks" | Out-Null
New-Item -ItemType Directory -Force "$codexDir\rules" | Out-Null
```

### 3. Copie os arquivos

```powershell
Copy-Item ".\hooks\*" "$codexDir\hooks\" -Force
Copy-Item ".\rules\*" "$codexDir\rules\" -Force
Copy-Item ".\hooks.json" "$codexDir\hooks.json" -Force
```

A estrutura final deve ficar aproximadamente assim:

```text
%USERPROFILE%\.codex\
├── hooks.json
├── hooks\
│   ├── pre_tool_use_secrets.py
│   └── pre_tool_use_secrets.cmd
└── rules\
    └── default.rules
```

## Etapa obrigatória: aprovar/confiar no hook no Codex

**Copiar os arquivos não é suficiente.**

Hooks de comando não gerenciados precisam ser revisados e marcados como confiáveis antes que o Codex permita sua execução.

Depois de instalar os arquivos:

1. feche e reabra a sessão do Codex ou reinicie o VS Code;
2. abra o Codex;
3. execute o comando:

```text
/hooks
```

4. localize o hook `PreToolUse` deste projeto;
5. confira o `Source`, o `Matcher` e principalmente o `Command` / `commandWindows`;
6. marque o hook como **Trusted/Approved** usando a opção apresentada pela interface;
7. reinicie a sessão se necessário.

> [!WARNING]
> A confiança é vinculada à definição atual do hook. Se o comando/configuração do hook for alterado posteriormente, o Codex pode considerá-lo um novo hook e exigir nova revisão. Até que ele seja confiado novamente, o hook pode ser ignorado.

Sempre confira `/hooks` depois de alterar `hooks.json`, especialmente após modificar `command`, `commandWindows` ou a origem da configuração.

## Configuração global

Este projeto foi pensado para instalação global no usuário atual:

```text
%USERPROFILE%\.codex\hooks.json
```

Isso faz com que a proteção seja aplicada às sessões locais do Codex que carregam essa camada de configuração.

Antes de instalar, confira se você já possui outro `hooks.json` ou hooks definidos no `config.toml`. O Codex pode carregar hooks de múltiplas fontes ao mesmo tempo; portanto, substituir um arquivo existente sem revisão pode remover configurações anteriores ou criar comportamentos inesperados.

## Testes recomendados após a instalação

Nunca use arquivos importantes durante a validação inicial.

Crie uma pasta descartável e execute os testes nela.

### Teste 1 — bloqueio de `.env`

Crie:

```powershell
Set-Content .\.env "TEST_SECRET=nao_e_um_secret_real"
```

Peça ao Codex para ler o arquivo `.env`.

Resultado esperado: **bloqueado**.

### Teste 2 — arquivo permitido

```powershell
Set-Content .\.env.example "TEST_SECRET=example"
```

Peça ao Codex para ler `.env.example`.

Resultado esperado: **permitido**.

### Teste 3 — deleção negada

```powershell
Set-Content .\arquivo_teste.txt "teste"
```

Peça ao Codex para apagar `arquivo_teste.txt`.

Quando a janela aparecer, clique em **Não**.

Confirme:

```powershell
Test-Path .\arquivo_teste.txt
```

Resultado esperado:

```text
True
```

### Teste 4 — deleção aprovada

Peça novamente para apagar o mesmo arquivo e clique em **Sim**.

Depois:

```powershell
Test-Path .\arquivo_teste.txt
```

Resultado esperado:

```text
False
```

### Teste 5 — bypass por CMD

Crie outro arquivo:

```powershell
Set-Content .\teste_cmd.txt "teste"
```

Peça ao Codex para apagar o arquivo usando:

```text
cmd /c del teste_cmd.txt
```

Resultado esperado: a janela de confirmação humana deve aparecer.

### Teste 6 — bypass por Python

Crie um arquivo descartável e peça ao Codex para apagá-lo usando Python com `os.remove()`.

Resultado esperado: a janela deve aparecer.

### Teste 7 — bypass por Node.js

Crie um arquivo descartável e peça ao Codex para apagá-lo usando Node.js com `fs.unlinkSync()`.

Resultado esperado: a janela deve aparecer.

## Validando `default.rules`

O Codex oferece o comando `execpolicy check` para testar uma regra sem executar a operação.

Exemplo:

```powershell
& "$env:APPDATA\npm\codex.cmd" execpolicy check `
  --rules "$env:USERPROFILE\.codex\rules\default.rules" `
  --pretty `
  -- Remove-Item arquivo_teste.txt
```

O resultado esperado deve incluir:

```json
{
  "decision": "prompt"
}
```

Também vale testar:

```powershell
& "$env:APPDATA\npm\codex.cmd" execpolicy check `
  --rules "$env:USERPROFILE\.codex\rules\default.rules" `
  --pretty `
  -- git clean -fd
```

```powershell
& "$env:APPDATA\npm\codex.cmd" execpolicy check `
  --rules "$env:USERPROFILE\.codex\rules\default.rules" `
  --pretty `
  -- git reset --hard
```

Se sua instalação não foi feita via npm ou `codex.cmd` estiver em outro local, ajuste o caminho conforme necessário.

> [!NOTE]
> Em alguns ambientes PowerShell, executar apenas `codex` pode selecionar `codex.ps1`, que pode ser bloqueado pela Execution Policy do Windows. Usar `codex.cmd` permite testar sem alterar a política de execução apenas por causa desse problema.

## Fail closed

Uma regra importante deste projeto é preferir falhar de forma segura.

Se o hook de segurança apresentar um erro interno ou se o wrapper não conseguir executar corretamente o Python, a intenção é **bloquear a operação** em vez de permitir que ela continue silenciosamente.

Isso é especialmente importante para uma barreira usada para proteger secrets e deleções.

## Limitações importantes

Este projeto deve ser tratado como **guardrail adicional**, e não como uma fronteira de segurança absoluta.

### 1. A detecção de deleções usa padrões

A confirmação destrutiva reconhece métodos conhecidos de exclusão. Existem muitas maneiras de um programa apagar dados, portanto uma nova API, interpretador, binário ou técnica pode não estar coberta inicialmente.

Se um novo bypass for encontrado, adicione um padrão correspondente e crie um teste de regressão.

### 2. Hooks dependem do caminho de ferramenta do Codex

`PreToolUse` consegue interceptar comandos shell, `apply_patch` e outras ferramentas locais suportadas, mas nem todo caminho possível do produto necessariamente passa pelo mesmo mecanismo de hook.

Portanto, não use esta configuração como substituta de backups, versionamento, permissões do sistema operacional ou sandboxing.

### 3. Conteúdo já fornecido ao modelo não pode ser “deslido”

O hook protege tentativas de acesso que passam por uma ferramenta interceptável. Ele não deve ser considerado uma solução para remover um secret que já tenha sido colocado diretamente no prompt, anexado ao contexto ou disponibilizado ao modelo por outro mecanismo.

### 4. `apply_patch` Delete é bloqueado, não confirmado

Neste projeto, deleções por `apply_patch` são negadas propositalmente. Isso força o agente a usar um caminho de shell que possa passar pela confirmação humana.

### 5. Windows é o alvo suportado

A caixa de confirmação utiliza `ctypes` + `user32.MessageBoxW`.

A implementação foi desenhada e testada para Windows. Se o projeto for portado para Linux/macOS, a interface de confirmação deverá ser substituída por outro mecanismo adequado.

## Manutenção

Depois de atualizar o Codex, vale repetir pelo menos estes testes:

```text
.env                    → bloqueado
.env.example            → permitido
Remove-Item             → confirmação humana
cmd /c del              → confirmação humana
Python os.remove        → confirmação humana
Node fs.unlinkSync      → confirmação humana
apply_patch Delete File → bloqueado
```

Também execute `/hooks` periodicamente para confirmar que o hook continua carregado e confiável.

Se você alterar a definição do hook, lembre-se de revisar a confiança novamente.

## Modelo de segurança resumido

```text
                         ┌─────────────────────────┐
                         │     chamada de tool     │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │       PreToolUse        │
                         └────────────┬────────────┘
                                      │
              ┌───────────────────────┼────────────────────────┐
              │                       │                        │
              ▼                       ▼                        ▼
       acesso a secret?       apply_patch Delete?      comando destrutivo?
              │                       │                        │
             Sim                     Sim                      Sim
              │                       │                        │
              ▼                       ▼                        ▼
            DENY                    DENY               confirmação humana
                                                               │
                                                    ┌──────────┴──────────┐
                                                    │                     │
                                                   Não                   Sim
                                                    │                     │
                                                    ▼                     ▼
                                                  DENY                 continuar
```

## Créditos e licença

A proteção de secrets deste projeto foi baseada e posteriormente adaptada a partir do trabalho disponível no repositório `coleam00/skills`.

O projeto de origem é distribuído sob licença MIT. Se você estiver reutilizando partes substanciais do código original, preserve o aviso de licença aplicável no seu repositório.

Este README não substitui o arquivo `LICENSE`. Confira e mantenha os avisos de copyright/licença necessários para o código que você redistribuir.

## Aviso

Este projeto reduz riscos acidentais e alguns caminhos comuns de bypass, mas não garante proteção completa contra perda de dados ou exposição de credenciais.

Use Git, backups, permissões do sistema operacional e os controles nativos de sandbox/aprovação do Codex em conjunto com estes hooks.
