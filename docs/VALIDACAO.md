# Validação local da versão v0.1.0

**Data:** 9 de novembro de 2026. **Escopo:** ambiente de execução local disponível durante o desenvolvimento; nenhuma execução remota no GitHub Actions foi realizada antes da criação/publicação do repositório.

## Execução de testes

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -q
```

**Resultado:** 128 testes automatizados aprovados, sem falhas.

Os casos cobrem parser e *drop-ins*, validação estrita de JSON, contratos separados, todas as 24 regras, sinalização de ciclos, classificações de risco, estabilidade de fingerprints, regressões, saída JSON/SARIF, proteção contra sobrescrita, compatibilidade da CLI e integridade do release.

## Cobertura

```bash
PYTHONPATH=src:tests python -m coverage run --branch --source=unitgraph_guard -m unittest discover -s tests -q
python -m coverage report -m
```

Resultado medido localmente: **95% de cobertura combinada de linhas e ramificações**. A cobertura é um indicador de execução de código, não garantia de inexistência de bugs.

## Verificações de distribuição

- Compilação `python -m compileall -q src tests scripts`: aprovada.
- Compilação do Wheel `python -m pip wheel --no-deps --no-build-isolation . -w dist`: aprovada.
- Instalação do Wheel em diretório isolado, sem dependências adicionais e sem acesso ao índice de pacotes: aprovada.
- CLI instalada: `--version` retorna `0`; auditoria de baseline retorna `0`; comparação com candidato inseguro retorna `2`.
- ZIP determinístico, manifesto SHA-256 por arquivo e checksums dos artefatos: verificados.
- YAML de CI, release e Dependabot: validado sintaticamente.

## Ações pendentes após a criação do repositório

1. Enviar o commit inicial para a branch `main`.
2. Aguardar resultados reais de CI em Ubuntu, Windows e macOS (Python 3.11, 3.12 e 3.13).
3. Corrigir quaisquer falhas dependentes de plataforma; repetir toda a matriz.
4. Publicar o release `v0.1.0` somente depois de a matriz aprovar o commit exato do HEAD de `main`.
5. Conferir tag, release, commit da `main` e SHA-256 dos artefatos publicados.

**Não declarar CI ou release publicados antes dessas etapas.**
