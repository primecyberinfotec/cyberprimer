# 🚀 Guia de Deploy — Cyber Primer Scanner

## Visão Geral da Arquitetura

```
Cliente (navegador)
       │
       ▼
GitHub Pages ──────────── Seu site estático (servicos.html)
       │                  primecyberinfotec.github.io/cyberprimer
       │
       │  GET /demo?domain=...
       ▼
 Render.com ────────────── API Python (FastAPI + módulos do scanner)
                           seu-app.onrender.com
```

**Por que dois serviços?**
GitHub Pages só serve arquivos HTML/CSS/JS estáticos. O scanner é Python — 
precisa de um servidor real. O Render.com oferece tier gratuito que roda Python.

---

## PASSO 1 — Preparar o repositório no GitHub

### 1.1 Estrutura de arquivos após o deploy:

```
seu-repositorio/
├── index.html
├── quem-somos.html
├── servicos.html          ← arquivo que criamos
├── contato.html
├── style.css
│
├── api/                   ← PASTA NOVA — backend
│   ├── main.py
│   └── requirements.txt
│
└── modules/               ← PASTA DO SCANNER (já existe)
    ├── __init__.py
    ├── dns_enum.py
    ├── ip_info.py
    ├── osint.py
    ├── port_scanner.py
    ├── ssl_checker.py
    ├── vuln_check.py
    ├── web_info.py
    └── ... (outros módulos)
```

### 1.2 Fazer upload:

1. Abra seu repositório no GitHub
2. Arraste e solte os arquivos `api/main.py` e `api/requirements.txt`
3. Substitua o `servicos.html` pelo novo (arraste por cima do antigo)
4. Confirme o commit: mensagem `"feat: scanner demo + pricing"`

---

## PASSO 2 — Deploy da API no Render.com

### 2.1 Criar conta (gratuita)

→ Acesse: https://render.com
→ "Get Started" → "Sign up with GitHub"
→ Autorize o Render a acessar seus repositórios

### 2.2 Criar o Web Service

1. No dashboard do Render, clique em **"+ New"** → **"Web Service"**
2. Selecione seu repositório GitHub
3. Configure assim:

| Campo              | Valor                                      |
|--------------------|--------------------------------------------|
| **Name**           | `cyberprimer-scanner` (ou qualquer nome)   |
| **Region**         | `Ohio (US East)` (mais rápido para BR)     |
| **Branch**         | `main`                                     |
| **Root Directory** | `api`                                      |
| **Runtime**        | `Python 3`                                 |
| **Build Command**  | `pip install -r requirements.txt`          |
| **Start Command**  | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| **Instance Type**  | `Free`                                     |

4. Clique em **"Create Web Service"**
5. Aguarde ~3 minutos para o primeiro build
6. O Render vai gerar uma URL como:
   ```
   https://cyberprimer-scanner.onrender.com
   ```
   **Copie essa URL!**

### 2.3 Verificar se está rodando

Acesse no navegador:
```
https://cyberprimer-scanner.onrender.com/health
```

Você deve ver:
```json
{"status": "ok", "service": "Cyber Primer Scanner API"}
```

---

## PASSO 3 — Conectar o site à API

### 3.1 Editar o servicos.html

Abra o `servicos.html` e encontre a linha (perto do final, no `<script>`):

```javascript
const API_BASE = 'https://SEU-APP-AQUI.onrender.com';
```

Troque pelo URL que o Render gerou:

```javascript
const API_BASE = 'https://cyberprimer-scanner.onrender.com';
```

### 3.2 Liberar o CORS na API

Abra `api/main.py` e encontre:

```python
ALLOWED_ORIGINS = [
    "https://primecyberinfotec.github.io",
    ...
]
```

Certifique-se que a URL do seu GitHub Pages está ali.
O GitHub Pages normalmente é `https://SEU-USUARIO.github.io`.

### 3.3 Fazer commit do servicos.html atualizado

Suba a versão com a URL correta para o GitHub.

---

## PASSO 4 — Testar tudo

1. Acesse seu site: `https://primecyberinfotec.github.io/cyberprimer/servicos.html`
2. Digite um domínio no scanner (ex: `animaiseciabrasil.com.br`)
3. Clique em "Analisar →"
4. Aguarde o terminal animado (~15 segundos)
5. O resultado deve aparecer com score, status cards e alertas

---

## ⚠️ Comportamento do Render Free Tier

O plano gratuito do Render **"dorme"** após 15 minutos sem uso.
Quando o primeiro usuário acessar depois de um período inativo:
- O servidor leva ~30–50 segundos para "acordar"
- A mensagem "Tempo limite excedido — aguarde 30s" vai aparecer
- Na segunda tentativa já funciona normalmente

**Para evitar isso** (opcional):
- Crie uma conta no https://cron-job.org
- Configure um job para chamar `https://SEU-APP.onrender.com/health` a cada 10 minutos
- Isso mantém o servidor "acordado" 24/7

---

## Fluxo de Pagamento — Como Funciona

```
Cliente usa demo gratuita
          │
          ▼
Clica em "Relatório Completo — R$ 197"
          │
          ▼
Modal Pix abre com:
  - Chave: 51.698.369/0001-50
  - Instruções passo a passo
          │
          ▼
Cliente faz o Pix e clica:
  "Enviar Comprovante no WhatsApp"
          │
          ▼
WhatsApp abre com mensagem pré-preenchida
  "Quero o Plano Profissional (R$ 197). Segue comprovante."
          │
          ▼
VOCÊ recebe o WhatsApp:
  1. Confirma o Pix no app do banco
  2. Roda: python main.py -t DOMINIO_DO_CLIENTE --ports top100 --json
  3. Gera os 4 relatórios HTML
  4. Compacta em ZIP e envia ao cliente
```

---

## Segurança — O que a API expõe

A rota `/demo` retorna APENAS:
- ✅ Score e composição de penalidades
- ✅ IP principal e geolocalização (público)
- ✅ Se SSL é válido e quantos dias restam
- ✅ Se SPF/DMARC existem (público via DNS)
- ✅ Percentual de cabeçalhos HTTP
- ✅ Contagem de breaches no HIBP
- ✅ Até 8 risk flags
- ✅ Contagem de subdomínios (não a lista)

A API **NÃO expõe**:
- ❌ Lista de portas abertas
- ❌ Lista de subdomínios
- ❌ CVEs detalhados
- ❌ Dados internos de servidor

---

## Resumo dos Comandos

```bash
# Testar a API localmente antes do deploy
cd api
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Testar no navegador:
# http://localhost:8000/health
# http://localhost:8000/demo?domain=google.com
```

---

## Dúvidas?

📧 primecyberinfotec@gmail.com
📲 WhatsApp: (66) 99226-3383
