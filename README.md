# UnitGraph Guard

[![CI](https://github.com/felipewatter/unitgraph-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/unitgraph-guard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/felipewatter/unitgraph-guard)](https://github.com/felipewatter/unitgraph-guard/releases)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)](pyproject.toml)
[![MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Auditoria offline de segurança de serviços `systemd`, relações de inicialização e regressões de configuração para equipes de segurança e operação de TI.**

> Importante: é um **analisador estático conservador de snapshots declarativos**, não um substituto do `systemd-analyze security`, do `systemd-analyze verify` nem de verificações no host. Não executa comandos do snapshot, não se conecta a servidores e não aplica alterações à infraestrutura.

Leia também a [versão em inglês](README.en.md), o [modelo de ameaças](docs/THREAT_MODEL.md) e o [catálogo de regras](docs/RULES.md).

## 1. Problema operacional

Mudanças em arquivos `.service` e *drop-ins* podem elevar privilégios, remover o isolamento do filesystem, criar dependências de inicialização cíclicas e introduzir persistência insegura. Revisões manuais desses arquivos normalmente não registram **qual risco foi introduzido** em relação à configuração aprovada.

O **UnitGraph Guard** usa um snapshot explícito de unidades e um contrato de segurança independente para gerar evidências reproduzíveis. Em uma revisão de mudança, ele responde:

- O serviço passou a executar como `root`?
- Um *drop-in* substituiu `ExecStart=` por um comando com prefixo de bypass de privilégios (`+` ou `!`)?
- Surgiram variáveis de ambiente com nomes sugestivos de segredos (sem expor os valores)?
- O serviço recebeu novas capacidades perigosas, acesso gravável excessivo ou hardening insuficiente?
- O grafo de `After=` / `Before=` contém ciclos entre unidades presentes no snapshot?
- Um serviço crítico passou a depender de um serviço privilegiado ou de dependência proibida?
- O risco é **novo**, **persistente** ou **resolvido** na mudança proposta?

## 2. Funcionalidades

| Área | Implementação |
|---|---|
| Análise de serviços | Composição explícita de `*.service` e *drop-ins* nomeados |
| Hardening | 24 regras rastreáveis com severidade e identificador estável |
| Privilégios | `User=`, `DynamicUser=`, `NoNewPrivileges=`, capacidades, prefixos de execução |
| Filesystem | `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `ReadWritePaths=`, `BindPaths=` |
| Kernel | `ProtectKernelModules=`, `ProtectKernelTunables=`, `ProtectControlGroups=` |
| Redução de superfície | `RestrictAddressFamilies=`, `SystemCallFilter=`, `UMask=` |
| Grafo | Relações de ordenação, ciclos por componentes fortemente conectados, dependências |
| Contratos confiáveis | Unidades críticas, exceções explícitas para root, dependências proibidas e modo estrito |
| Auditoria de mudanças | `new`, `resolved`, `persistent`; gate por severidade apenas para riscos novos |
| Exportação | JSON estável, SARIF 2.1.0, fingerprints SHA-256 |
| Proteções do parser | Entrada limitada, rejeição de duplicatas JSON, NaN, symlinks e estruturas inválidas |
| Segurança de exportação | Arquivos criados exclusivamente, sem sobrescrever entradas ou relatórios existentes |
| Automação | GitHub Actions 3 sistemas operacionais × 3 versões Python; release imutável condicionado à CI |

## 3. Instalação

Requer **Python 3.11 ou superior**. Não exige dependências de runtime além da biblioteca padrão.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --no-deps -e .
unitgraph --version
```

Também pode ser executado sem instalar, após definir `PYTHONPATH=src`:

```bash
PYTHONPATH=src python -m unitgraph_guard --help
```

## 4. Uso rápido

### 4.1 Auditar uma configuração previamente exportada

```bash
unitgraph audit \
  --candidate examples/baseline.json \
  --policy examples/policy.json \
  --fail-on high
```

Resultado esperado: código `0` e `"verdict": "pass"`.

### 4.2 Simular uma mudança insegura

```bash
unitgraph audit \
  --candidate examples/candidate-risky.json \
  --policy examples/policy.json \
  --fail-on high
```

Resultado esperado: código `2`, com findings como **UG001** (identidade privilegiada), **UG002** (prefixo `+`), **UG005** (escrita ampla) e **UG018** (executável sob `/tmp`).

### 4.3 Comparar baseline e candidato

```bash
unitgraph compare \
  --baseline examples/baseline.json \
  --candidate examples/candidate-risky.json \
  --policy examples/policy.json \
  --fail-on medium
```

Somente findings **novos** são considerados para o bloqueio; os persistentes ficam registrados como dívida conhecida e os resolvidos como evidência de remediação. Isso **não** implica que findings persistentes sejam aceitáveis em produção.

### 4.4 Exportar JSON e SARIF

```bash
unitgraph compare \
  --baseline examples/baseline.json \
  --candidate examples/candidate-risky.json \
  --policy examples/policy.json \
  --fail-on none \
  --output review-report.json \
  --sarif review-report.sarif
```

Os dois destinos precisam ser **arquivos novos**, em diretórios existentes; o programa recusa sobrescrever arquivos, inclusive snapshots e contratos. Na comparação, o SARIF apresenta os riscos **novos**.

### 4.5 Códigos de saída

| Código | Significado |
|---|---|
| `0` | Auditoria concluída, sem violação do limiar de bloqueio |
| `2` | Findings no limiar configurado: mudança bloqueada |
| `3` | Entrada inválida, erro seguro de leitura ou gravação |

Erros de sintaxe de comandos e argumentos inválidos usam o código padrão `2` do `argparse`.

## 5. Modelo de entrada

O usuário fornece um JSON **com o conteúdo do `.service` e dos *drop-ins***. Não são aceitos caminhos remotos nem comandos a executar. O arquivo deve ser extraído de uma fonte confiável e analisado durante uma revisão de mudança.

Exemplo reduzido:

```json
{
  "schemaVersion": 1,
  "units": [
    {
      "name": "web.service",
      "content": "[Unit]\nDescription=Web\n[Service]\nUser=web\nExecStart=/usr/local/bin/web\nNoNewPrivileges=yes\nProtectSystem=strict\n",
      "dropins": [
        {"name": "90-override.conf", "content": "[Service]\nPrivateTmp=yes\n"}
      ]
    }
  ]
}
```

**Atenção:** o texto `content` é tratado como **dados**, nunca como comando a executar. O parser aplica somente um subconjunto documentado das regras de composição do systemd. A implementação reconhece ordenação alfanumérica de *drop-ins* e o reset explícito de diretivas de lista, mas **não** resolve automaticamente diretórios em `/etc`, `/run`, `/usr/lib`, aliases, templates, generadores, specifiers `%`, herança de gestores ou o estado efetivo do kernel. Para a configuração final real, exporte e valide também com `systemctl cat`, `systemd-analyze verify` e `systemd-analyze security` no host apropriado.

Consulte [docs/SCHEMA.md](docs/SCHEMA.md) para limites, sintaxe suportada e exemplos de contratos.

## 6. Contrato de segurança separado

Exemplo de `policy.json`:

```json
{
  "schemaVersion": 1,
  "criticalUnits": ["web.service", "database.service"],
  "allowedRootUnits": [],
  "forbiddenDependencies": ["rescue.target", "debug-root.service"],
  "strictDependencies": false
}
```

Mantenha esse contrato sob revisão de código, **separado** do snapshot submetido pelo autor da mudança. Uma alteração que simplesmente modifique sua própria lista de exceções não deve ser tratada como uma aprovação legítima. A regra `UG023` sinaliza relações com serviços privilegiados somente quando a unidade de origem consta em `criticalUnits`.

## 7. Regras e classificação

Há **24 regras (UG001–UG024)**, com classificações `low`, `medium`, `high` e `critical`. O conjunto inclui:

- Escalada de privilégio e bypass `ExecStart=+` / `!`.
- Redução de mecanismos de isolamento do filesystem e kernel.
- Capabilidades potencialmente perigosas e chamadas ao shell.
- Caminhos amplamente graváveis e executáveis sob diretórios compartilhados.
- Exposição de **nomes** de variáveis de ambiente que indicam credenciais, sem imprimir valores.
- Dependências proibidas, ciclos de ordenação e relações críticas com unidades privilegiadas.

**A ausência de uma regra não comprova segurança.** Cada finding é uma evidência estática, sujeita a contexto e validação humana. Veja a [tabela integral de regras](docs/RULES.md).

## 8. Arquitetura

```text
Snapshot baseline (.json) ───┐
                             ├──> JSON estrito ──> parser .service/drop-ins ──> configurações efetivas ──┐
Snapshot candidato (.json) ──┘                                                                │
                                                                                           │
Contrato aprovado (.json) ─────────────> regras de hardening + grafo de dependências ────────┤
                                                                                           │
                                                                                  findings SHA-256
                                                                                           │
                                                                     diff + gate ──> JSON / SARIF
```

O motor não acessa rede, não invoca `systemctl`, não usa shell com dados do snapshot e não depende de APIs externas. O processo de release gera ZIP, pacote Wheel, manifesto por arquivo e checksums verificáveis. Veja [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 9. CI/CD e publicação

O workflow [`ci.yml`](.github/workflows/ci.yml) executa os testes em **Ubuntu, Windows e macOS** com Python **3.11, 3.12 e 3.13**. A CI inclui regressões, compilação, análise da configuração segura, teste de bloqueio do candidato inseguro e geração do Wheel.

O workflow [`release.yml`](.github/workflows/release.yml):

1. É iniciado somente após a conclusão do workflow **CI**.
2. Exige CI **aprovada**, evento original **push** na `main` e origem no próprio repositório.
3. Revalida que o commit testado é exatamente o HEAD atual da `main`.
4. Verifica a correspondência entre a versão declarada no `pyproject.toml` e no módulo Python.
5. Repete os testes no runner de publicação e gera o Wheel, ZIP e checksums SHA-256.
6. Publica uma nova tag imutável; se o release já existir, não substitui os artefatos.

**Não é necessário configurar segredos externos** para o fluxo padrão: ele usa o token temporário do GitHub Actions com permissão `contents: write` somente no job de publicação. Mantenha permissões de workflows e proteção da `main` configuradas conforme a política do repositório.

## 10. Testes e desenvolvimento

```bash
python -m pip install --no-deps -e .
python -m compileall -q src tests scripts
python -m unittest discover -s tests -v
python scripts/build_release.py dist
```

Para testes com cobertura, pode instalar `coverage` separadamente no ambiente de desenvolvimento; não é dependência do projeto em runtime.

## 11. Limitações e cuidados

- O projeto inspeciona **serviços `.service`**, não gera uma visão exaustiva de sockets, timers, targets, mounts, automounts ou user managers.
- Não interpreta completamente expansão de specifiers, escapar de nomes, aliases, templates, `EnvironmentFile` externo, credenciais carregadas em runtime, DBus, PAM, grupos ou permissões reais de diretórios.
- O grafo de ciclos usa apenas `After=` / `Before=` entre unidades **incluídas** no snapshot; não prova ausência de ciclos globais.
- Detectar `ExecStart=/bin/sh -c` é um **sinal de revisão**, não prova injeção de comandos.
- Não verifica se as diretivas são suportadas pelo systemd/kernel do host.
- Resultados não substituem revisão humana, testes em staging, controle de mudanças ou avaliação de riscos.
- O mecanismo de criação exclusiva de relatórios protege contra sobrescrita simples, mas diretórios de saída devem ser confiáveis.

**Segurança operacional:** evite incluir segredos reais no snapshot. O parser mantém strings em memória para avaliação, embora os relatórios não exibam valores de variáveis sinalizadas. Use exemplos sintéticos, revisão de PR e ambientes controlados.

## 12. Governança

- [SECURITY.md](SECURITY.md): divulgação responsável, escopo e restrições.
- [CONTRIBUTING.md](CONTRIBUTING.md): instalação e contribuição.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): código de conduta.
- [CHANGELOG.md](CHANGELOG.md): histórico de versão.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): ameaças e controles.
- [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md): release v0.1.0.
- [docs/VALIDACAO.md](docs/VALIDACAO.md): evidências dos testes locais e condições da publicação.
- [LICENSE](LICENSE): MIT.

## 13. Fontes técnicas

- [systemd.unit(5): composição, *drop-ins* e dependências](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).
- [systemd.exec(5): sandboxing, capacidades e controles de execução](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
- [systemd.service(5): semântica de `ExecStart` e serviços](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
- [systemd-analyze(1): `security` e `verify`](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html).
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

---

**Criado por Felipe Watter.** Projeto público de pesquisa aplicada em segurança de serviços Linux e operações de TI. Contribuições, testes adicionais e revisões de regras são bem-vindos.
