/* Enigma da Rede Quiral: caveira escondida no rodapé -> portão de senha -> terminal.
 *
 * Configuração (feita pelo admin) fica em quiral_config/enigma no Firebase
 * (aninhado em quiral_config porque as regras só aceitam chaves de topo
 * conhecidas). Senhas e textos secretos NUNCA ficam em claro lá: cada
 * segredo é cifrado com AES-GCM usando a própria senha (PBKDF2), então quem
 * abrir o DevTools só vê lixo cifrado - o texto só sai com a senha certa. */
(function () {
  'use strict';

  const CFG_URL = 'https://quiral-f97a2-default-rtdb.firebaseio.com/quiral_config/enigma.json';
  const LS_PLAYER = 'quiral_enigma_v1';
  const LS_ADMIN = 'quiral_enigma_admin_v1';
  const MARCA_PORTAO = 'QUIRAL';
  const reduceMotion = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- cripto ---------- */
  const enc = new TextEncoder(), dec = new TextDecoder();
  const norm = (s) => String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim().replace(/\s+/g, ' ').toUpperCase();
  const b64 = (buf) => { let s = ''; new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveKey(senha, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(norm(senha)), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function cifrar(senha, texto) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(senha, salt);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(texto));
    return { s: b64(salt), i: b64(iv), c: b64(ct) };
  }
  async function decifrar(senha, pack) {
    if (!pack || !pack.s || !pack.i || !pack.c) return null;
    try {
      const key = await deriveKey(senha, unb64(pack.s));
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(pack.i) }, key, unb64(pack.c));
      return dec.decode(pt);
    } catch (e) { return null; }
  }

  /* ---------- estado local do jogador (só neste aparelho) ---------- */
  function lerLS(chave) { try { return JSON.parse(localStorage.getItem(chave)) || {}; } catch (e) { return {}; } }
  function gravarLS(chave, obj) { try { localStorage.setItem(chave, JSON.stringify(obj)); } catch (e) { /* modo privado */ } }

  async function buscarConfig() {
    const res = await fetch(CFG_URL + '?nocache=' + Date.now());
    if (!res.ok) throw new Error('http ' + res.status);
    return res.json();
  }

  /* ---------- CSS ---------- */
  const CSS = `
  #en-overlay{position:fixed;inset:0;z-index:9000;background:#000;color:#00ff41;font-family:'Share Tech Mono',monospace;display:flex;align-items:center;justify-content:center;padding:16px;overflow:hidden}
  #en-overlay[hidden]{display:none!important}
  #en-overlay [hidden]{display:none!important}
  #en-rain{position:absolute;inset:0;width:100%;height:100%;opacity:.55}
  .en-scan{position:absolute;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(0,0,0,.28) 0,rgba(0,0,0,.28) 1px,transparent 1px,transparent 3px)}
  .en-vig{position:absolute;inset:0;pointer-events:none;background:radial-gradient(ellipse at center,transparent 35%,rgba(0,0,0,.92) 100%)}
  .en-close{position:absolute;top:12px;right:14px;z-index:3;background:rgba(0,12,0,.8);color:#00ff41;border:1px solid #0a7a24;padding:6px 12px;font:inherit;font-size:13px;cursor:pointer;letter-spacing:1px}
  .en-close:hover{background:#003b10;box-shadow:0 0 12px #00ff41}
  .en-panel{position:relative;z-index:2;width:100%;max-width:440px;background:rgba(0,10,0,.84);border:1px solid #0a7a24;box-shadow:0 0 28px rgba(0,255,65,.25),inset 0 0 40px rgba(0,60,10,.35);padding:22px 20px}
  .en-panel.en-wide{max-width:760px;height:min(88vh,720px);display:flex;flex-direction:column}
  .en-skull{margin:0 0 10px;font-size:13px;line-height:1.15;text-align:center;color:#00ff41;text-shadow:0 0 8px #00ff41;white-space:pre}
  .en-title{margin:0 0 4px;font-size:20px;letter-spacing:4px;text-align:center;text-shadow:0 0 10px #00ff41;animation:en-flicker 5s infinite}
  .en-sub{margin:0 0 16px;font-size:12px;color:#0fae3a;text-align:center;letter-spacing:2px}
  .en-input{width:100%;background:#000;color:#00ff41;border:1px solid #0a7a24;padding:10px 12px;font:inherit;font-size:16px;letter-spacing:2px;caret-color:#00ff41;outline:none;border-radius:0}
  .en-input:focus{border-color:#00ff41;box-shadow:0 0 12px rgba(0,255,65,.5)}
  .en-input::placeholder{color:#0a5a1c}
  .en-btn{background:#002a0b;color:#00ff41;border:1px solid #00ff41;padding:9px 16px;font:inherit;font-size:14px;letter-spacing:2px;cursor:pointer}
  .en-btn:hover:not(:disabled){background:#004d17;box-shadow:0 0 14px #00ff41}
  .en-btn:disabled{opacity:.45;cursor:default}
  .en-status{min-height:20px;margin:12px 0 0;font-size:13px;text-align:center;color:#0fae3a}
  .en-status.en-bad{color:#ff3b3b;text-shadow:0 0 8px #ff0000}
  .en-head{display:flex;justify-content:space-between;align-items:baseline;gap:8px;border-bottom:1px solid #0a7a24;padding-bottom:8px;margin-bottom:10px;font-size:13px;letter-spacing:2px;padding-right:96px}
  .en-head b{text-shadow:0 0 8px #00ff41;font-weight:normal}
  .en-log{flex:1;min-height:0;overflow-y:auto;font-size:14px;line-height:1.5;padding-right:4px}
  .en-log::-webkit-scrollbar,.en-data::-webkit-scrollbar{width:6px}
  .en-log::-webkit-scrollbar-thumb,.en-data::-webkit-scrollbar-thumb{background:#0a7a24}
  .en-line{white-space:pre-wrap;word-break:break-word;margin:0 0 4px}
  .en-you{color:#8dffa8}
  .en-msg{color:#c8ffd4;border-left:2px solid #00ff41;padding-left:10px;margin:8px 0;text-shadow:0 0 6px rgba(0,255,65,.6)}
  .en-err{color:#ff3b3b;text-shadow:0 0 8px #ff0000}
  .en-ok{color:#f0fff3;text-shadow:0 0 10px #00ff41}
  .en-whisper{color:#8a1a1a;font-style:italic}
  .en-data{max-height:34%;overflow-y:auto;margin-top:10px;display:flex;flex-direction:column;gap:8px}
  .en-block{border:1px solid #00ff41;background:rgba(0,40,10,.6);padding:10px 12px;box-shadow:0 0 14px rgba(0,255,65,.25)}
  .en-block h3{margin:0 0 6px;font-size:13px;letter-spacing:3px;font-weight:normal;color:#8dffa8}
  .en-block p{margin:0;font-size:16px;white-space:pre-wrap;word-break:break-word;color:#f0fff3;text-shadow:0 0 8px #00ff41}
  .en-block a{display:inline-block;margin-top:8px;color:#00ff41;font-size:13px;text-decoration:underline}
  .en-prompt{display:flex;gap:8px;align-items:center;margin-top:12px}
  .en-prompt span{color:#00ff41;font-size:18px;text-shadow:0 0 8px #00ff41}
  .en-prompt .en-input{flex:1}
  #en-overlay.en-glitch .en-panel{animation:en-shake .45s steps(2) 1;border-color:#ff2a2a;box-shadow:0 0 34px rgba(255,0,0,.55)}
  #en-overlay.en-glitch .en-title,#en-overlay.en-glitch .en-line{text-shadow:2px 0 #ff0000,-2px 0 #00ffff}
  @keyframes en-shake{0%{transform:translate(0,0)}20%{transform:translate(-6px,2px)}40%{transform:translate(5px,-3px)}60%{transform:translate(-4px,-2px)}80%{transform:translate(6px,3px)}100%{transform:translate(0,0)}}
  @keyframes en-flicker{0%,90%,100%{opacity:1}92%{opacity:.35}94%{opacity:1}96%{opacity:.5}}
  @media (prefers-reduced-motion:reduce){.en-title{animation:none}#en-overlay.en-glitch .en-panel{animation:none}}
  @media (max-width:520px){.en-panel{padding:16px 12px}.en-skull{font-size:11px}.en-head{padding-right:84px;font-size:12px}}
  `;
  function injetarCSS() {
    if (document.getElementById('en-css')) return;
    const st = document.createElement('style'); st.id = 'en-css'; st.textContent = CSS; document.head.appendChild(st);
  }

  /* ---------- chuva de caracteres ---------- */
  const GLIFOS = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEF<>/\\|=+*';
  let chuvaTimer = null, chuvaRaf = null;
  function iniciarChuva(canvas) {
    pararChuva();
    const ctx = canvas.getContext('2d');
    const tam = 16;
    let cols = 0, gotas = [];
    function ajustar() {
      canvas.width = canvas.clientWidth; canvas.height = canvas.clientHeight;
      cols = Math.ceil(canvas.width / tam);
      gotas = Array.from({ length: cols }, () => Math.floor(Math.random() * -20));
      ctx.fillStyle = '#000'; ctx.fillRect(0, 0, canvas.width, canvas.height);
    }
    ajustar();
    canvas._onresize = ajustar; window.addEventListener('resize', ajustar);
    const intervalo = reduceMotion ? 160 : 55;
    let ultimo = 0;
    function quadro(t) {
      chuvaRaf = requestAnimationFrame(quadro);
      if (t - ultimo < intervalo) return;
      ultimo = t;
      ctx.fillStyle = 'rgba(0,6,0,0.10)'; ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = tam + 'px "Share Tech Mono", monospace';
      for (let i = 0; i < cols; i++) {
        const ch = GLIFOS[Math.floor(Math.random() * GLIFOS.length)];
        const y = gotas[i] * tam;
        const r = Math.random();
        ctx.fillStyle = r < 0.012 ? '#ff2a2a' : (r < 0.08 ? '#d8ffe0' : '#00ff41');
        if (y > 0) ctx.fillText(ch, i * tam, y);
        if (y > canvas.height && Math.random() > 0.972) gotas[i] = 0;
        gotas[i]++;
      }
    }
    chuvaRaf = requestAnimationFrame(quadro);
  }
  function pararChuva() {
    if (chuvaRaf) cancelAnimationFrame(chuvaRaf);
    chuvaRaf = null;
    const c = document.getElementById('en-rain');
    if (c && c._onresize) { window.removeEventListener('resize', c._onresize); c._onresize = null; }
  }

  /* ---------- overlay do jogador ---------- */
  const CAVEIRA_ASCII = [
    '    _______    ',
    '  .-"       "-.  ',
    ' /   _     _   \\ ',
    '|   (O)   (O)   |',
    ' \\      ^      / ',
    '  \\  \\_____/  /  ',
    '   |_|_|_|_|_|   ',
    '   |_|_|_|_|_|   '
  ].join('\n');

  const SUSSURROS = [
    '...ele ainda está aqui...',
    'não olhe para trás.',
    'SINAL ANÔMALO DETECTADO NO SETOR 7',
    'algo respirou no canal.',
    'quem está digitando além de você?',
    'a estática está falando.',
    '...eles ouvem o teclado...',
    'a tela piscou. não foi a tela.',
    'existe alguém na outra ponta da linha.',
    'ele aprendeu o seu nome pelo som das teclas.',
    'ALERTA: BATIMENTO CARDÍACO DETECTADO NO CANAL',
    'a nave não caiu. ela foi deixada aqui.',
    'as luzes do campo apagaram por um instante.',
    '...não responda quando ele chamar...',
    'algo raspa por baixo da estática.',
    'você já contou quantos são vocês?',
    'ERRO 0x666: PRESENÇA NÃO CATALOGADA',
    'o silêncio no rádio não é vazio.',
    'ele está mais perto do que o mapa mostra.',
    'não use lanterna. ele enxerga a luz.',
    '...alguém acabou de sussurrar atrás de você...',
    'a mata está quieta demais.',
    'SINAL DUPLICADO: ORIGEM DESCONHECIDA',
    'ele copia vozes. cuidado com quem chama pelo rádio.',
    'os passos no canal não são os seus.',
    'cada tentativa errada o acorda um pouco mais.',
    'a criatura não dorme. só espera.',
    'há algo respirando dentro da nave.',
    'não confie no companheiro que ficou calado.',
    'a temperatura caiu 12 graus no setor leste.',
    'SENSOR DE MOVIMENTO: 1 ALVO NÃO IDENTIFICADO',
    '...ele está rindo...',
    'os galhos se mexem sem vento.',
    'não fique sozinho. nunca fique sozinho.',
    'a estática formou uma palavra. era o seu nome.',
    'ele deixou marcas no chão. estavam frescas.',
    'CANAL COMPROMETIDO. ALGO ESTÁ LENDO ISTO.',
    'o eco respondeu antes da pergunta.',
    'não pisque por muito tempo.',
    'as sombras do campo estão em posições diferentes.',
    'alguém tocou no seu ombro? não olhe.',
    'ele sabe onde vocês vão. sempre soube.',
    'a última equipe que decifrou isto não voltou.',
    'FALHA NO SENSOR TÉRMICO: ALGO FRIO DEMAIS',
    'você ouviu isso? eu também.',
    'as luzes dos nós estão piscando em código.'
  ];
  // Sorteio sem repetição: embaralha todas as frases e só reembaralha depois
  // de mostrar cada uma (sem repetir a última na virada). A "sacola" fica fora
  // do overlay para não reiniciar quando o jogador fecha e reabre.
  let sacolaSussurros = [];
  let ultimoSussurro = null;
  function proximoSussurro() {
    if (!sacolaSussurros.length) {
      sacolaSussurros = SUSSURROS.slice();
      for (let i = sacolaSussurros.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [sacolaSussurros[i], sacolaSussurros[j]] = [sacolaSussurros[j], sacolaSussurros[i]];
      }
      if (sacolaSussurros[sacolaSussurros.length - 1] === ultimoSussurro) sacolaSussurros.unshift(sacolaSussurros.pop());
    }
    ultimoSussurro = sacolaSussurros.pop();
    return ultimoSussurro;
  }
  const NEGADOS = [
    'CHAVE INVÁLIDA.',
    'ACESSO NEGADO.',
    'ERRO 0xDEAD: PADRÃO NÃO RECONHECIDO.',
    'A ESTÁTICA RECUSOU SUA CHAVE.',
    'NADA RESPONDE... AINDA.'
  ];

  const el = {};            // referências do DOM
  let montado = false, ficha = 0, fila = Promise.resolve(), timerSussurro = null;
  let achados = {};          // { coord: {codigo, texto}, areas: {codigo, texto} }
  let focoAnterior = null;

  function montar() {
    if (montado) return;
    injetarCSS();
    const o = document.createElement('div');
    o.id = 'en-overlay'; o.hidden = true;
    o.setAttribute('role', 'dialog'); o.setAttribute('aria-modal', 'true'); o.setAttribute('aria-label', 'Canal restrito');
    o.innerHTML =
      '<canvas id="en-rain"></canvas><div class="en-scan"></div><div class="en-vig"></div>' +
      '<button type="button" class="en-close" id="en-close">[ SAIR ]</button>' +
      '<section class="en-panel" id="en-gate">' +
        '<pre class="en-skull" id="en-skull"></pre>' +
        '<h2 class="en-title">CANAL RESTRITO</h2>' +
        '<p class="en-sub">// IDENTIFIQUE-SE</p>' +
        '<input class="en-input" id="en-gate-input" type="text" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="insira a chave" aria-label="Chave de acesso">' +
        '<div style="display:flex;justify-content:flex-end;margin-top:12px"><button type="button" class="en-btn" id="en-gate-btn">ENTRAR</button></div>' +
        '<p class="en-status" id="en-gate-status" role="status"></p>' +
      '</section>' +
      '<section class="en-panel en-wide" id="en-term" hidden>' +
        '<div class="en-head"><b>REDE QUIRAL // CANAL PROIBIDO</b><span id="en-clock"></span></div>' +
        '<div class="en-log" id="en-log" aria-live="polite"></div>' +
        '<div class="en-data" id="en-data"></div>' +
        '<div class="en-prompt"><span>&gt;</span><input class="en-input" id="en-term-input" type="text" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="digite a chave..." aria-label="Inserir chave"><button type="button" class="en-btn" id="en-term-btn">ENVIAR</button></div>' +
      '</section>';
    document.body.appendChild(o);
    el.overlay = o;
    el.rain = o.querySelector('#en-rain');
    el.gate = o.querySelector('#en-gate');
    el.gateInput = o.querySelector('#en-gate-input');
    el.gateBtn = o.querySelector('#en-gate-btn');
    el.gateStatus = o.querySelector('#en-gate-status');
    el.term = o.querySelector('#en-term');
    el.log = o.querySelector('#en-log');
    el.data = o.querySelector('#en-data');
    el.termInput = o.querySelector('#en-term-input');
    el.termBtn = o.querySelector('#en-term-btn');
    el.clock = o.querySelector('#en-clock');
    o.querySelector('#en-skull').textContent = CAVEIRA_ASCII;

    o.querySelector('#en-close').addEventListener('click', fecharEnigma);
    el.gateBtn.addEventListener('click', tentarPortao);
    el.gateInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') tentarPortao(); });
    el.termBtn.addEventListener('click', enviarChave);
    el.termInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') enviarChave(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !el.overlay.hidden) fecharEnigma(); });
    montado = true;
  }

  function glitch() {
    if (reduceMotion) return;
    el.overlay.classList.remove('en-glitch'); void el.overlay.offsetWidth;
    el.overlay.classList.add('en-glitch');
    setTimeout(() => el.overlay.classList.remove('en-glitch'), 500);
  }
  const sortear = (lista) => lista[Math.floor(Math.random() * lista.length)];

  function rolar() { el.log.scrollTop = el.log.scrollHeight; }

  // Enfileira uma linha no terminal com efeito de digitação (na ordem em que foram pedidas).
  function dizer(texto, classe, instantaneo) {
    const minhaFicha = ficha;
    fila = fila.then(() => new Promise((ok) => {
      if (minhaFicha !== ficha) return ok();
      const d = document.createElement('div');
      d.className = 'en-line ' + (classe || '');
      el.log.appendChild(d);
      if (reduceMotion || instantaneo) { d.textContent = texto; rolar(); return ok(); }
      let i = 0;
      const passo = () => {
        if (minhaFicha !== ficha) return ok();
        d.textContent = texto.slice(0, ++i); rolar();
        if (i < texto.length) setTimeout(passo, 14); else ok();
      };
      passo();
    }));
    return fila;
  }

  function linkMapa(texto) {
    const m = String(texto).match(/(-?\d{1,3}\.\d+)\s*[,;\s]\s*(-?\d{1,3}\.\d+)/);
    return m ? 'https://www.google.com/maps?q=' + m[1] + ',' + m[2] : null;
  }

  function desenharAchados() {
    el.data.textContent = '';
    const defs = [['coord', '▼ LOCAL DO IMPACTO DA NAVE'], ['areas', '▼ ÁREAS DE POSSÍVEL PRESENÇA DA ENTIDADE']];
    defs.forEach(([tipo, titulo]) => {
      const a = achados[tipo]; if (!a) return;
      const b = document.createElement('div'); b.className = 'en-block';
      const h = document.createElement('h3'); h.textContent = titulo; b.appendChild(h);
      const p = document.createElement('p'); p.textContent = a.texto; b.appendChild(p);
      const url = tipo === 'coord' ? linkMapa(a.texto) : null;
      if (url) {
        const l = document.createElement('a'); l.href = url; l.target = '_blank'; l.rel = 'noopener noreferrer'; l.textContent = '[ ABRIR NO MAPA ]'; b.appendChild(l);
      }
      el.data.appendChild(b);
    });
  }

  function agendarSussurro() {
    clearTimeout(timerSussurro);
    if (reduceMotion) return;
    timerSussurro = setTimeout(() => {
      if (el.overlay.hidden || el.term.hidden) return;
      dizer(proximoSussurro(), 'en-whisper', true);
      agendarSussurro();
    }, 14000 + Math.random() * 14000);
  }

  function relogio() {
    if (el.overlay.hidden) return;
    el.clock.textContent = new Date().toLocaleTimeString('pt-BR');
    setTimeout(relogio, 1000);
  }

  async function entrarNoTerminal(cfg) {
    el.gate.hidden = true; el.term.hidden = false;
    el.log.textContent = ''; ficha++; fila = Promise.resolve();
    relogio();
    // revalida os códigos já resolvidos neste aparelho contra a configuração atual
    const salvo = lerLS(LS_PLAYER);
    achados = {};
    let mudou = false;
    for (const tipo of ['coord', 'areas']) {
      const cod = salvo.achados && salvo.achados[tipo];
      if (!cod) continue;
      const t = await decifrar(cod, cfg[tipo]);
      if (t !== null) achados[tipo] = { codigo: cod, texto: t };
      else { delete salvo.achados[tipo]; mudou = true; }
    }
    if (mudou) gravarLS(LS_PLAYER, salvo);
    desenharAchados();

    dizer('CONEXÃO ESTABELECIDA.', 'en-ok');
    dizer('ENLACE COM O CANAL PROIBIDO... OK', '');
    if (cfg.msg) { dizer('TRANSMISSÃO INTERCEPTADA:', ''); dizer(cfg.msg, 'en-msg'); }
    if (achados.coord || achados.areas) dizer('DADOS JÁ RECUPERADOS ESTÃO NO PAINEL ABAIXO.', 'en-ok');
    dizer('INSIRA A CHAVE_', '');
    agendarSussurro();
    setTimeout(() => el.termInput.focus(), 50);
  }

  function estadoPortao(texto, ruim) {
    el.gateStatus.textContent = texto;
    el.gateStatus.classList.toggle('en-bad', !!ruim);
  }

  async function tentarPortao() {
    const codigo = el.gateInput.value;
    if (!norm(codigo)) { estadoPortao('Digite a chave.', true); return; }
    el.gateBtn.disabled = true; estadoPortao('verificando...', false);
    try {
      const cfg = await buscarConfig();
      if (!cfg || !cfg.gate) { estadoPortao('CANAL SEM SINAL. Volte mais tarde.', true); return; }
      const t = await decifrar(codigo, cfg.gate);
      if (t === MARCA_PORTAO) {
        const salvo = lerLS(LS_PLAYER); salvo.portao = codigo; gravarLS(LS_PLAYER, salvo);
        estadoPortao('ACESSO CONCEDIDO.', false);
        setTimeout(() => entrarNoTerminal(cfg), reduceMotion ? 0 : 700);
      } else {
        estadoPortao(sortear(NEGADOS), true); glitch(); el.gateInput.select();
      }
    } catch (e) {
      estadoPortao('FALHA NO ENLACE. Verifique a conexão.', true);
    } finally { el.gateBtn.disabled = false; }
  }

  async function enviarChave() {
    const bruto = el.termInput.value;
    if (!norm(bruto)) return;
    el.termInput.value = ''; el.termBtn.disabled = true;
    dizer('> ' + bruto, 'en-you', true);
    try {
      const cfg = await buscarConfig();
      if (!cfg) { dizer('ERRO: CANAL SEM SINAL.', 'en-err'); return; }
      for (const tipo of ['coord', 'areas']) {
        const t = await decifrar(bruto, cfg[tipo]);
        if (t === null) continue;
        const novo = !achados[tipo];
        achados[tipo] = { codigo: bruto, texto: t };
        const salvo = lerLS(LS_PLAYER); salvo.achados = salvo.achados || {}; salvo.achados[tipo] = bruto; gravarLS(LS_PLAYER, salvo);
        desenharAchados();
        if (tipo === 'coord') {
          dizer(novo ? 'DECIFRADO. SINAL DE IMPACTO TRIANGULADO...' : 'CHAVE JÁ ACEITA. REEXIBINDO DADOS.', 'en-ok');
          dizer('COORDENADAS RECUPERADAS. VEJA O PAINEL ABAIXO.', 'en-ok');
        } else {
          dizer(novo ? 'RASTREADOR DA NAVE ATIVADO. VARRENDO O SETOR...' : 'CHAVE JÁ ACEITA. REEXIBINDO DADOS.', 'en-ok');
          dizer('ÁREAS DE PRESENÇA DETECTADAS. VEJA O PAINEL ABAIXO.', 'en-ok');
        }
        return;
      }
      glitch(); dizer(sortear(NEGADOS), 'en-err');
    } catch (e) {
      dizer('FALHA NO ENLACE. Tente de novo.', 'en-err');
    } finally { el.termBtn.disabled = false; el.termInput.focus(); }
  }

  async function abrirEnigma() {
    montar();
    focoAnterior = document.activeElement;
    ficha++; fila = Promise.resolve();
    el.overlay.hidden = false;
    document.body.style.overflow = 'hidden';
    el.term.hidden = true; el.gate.hidden = false;
    el.gateInput.value = ''; estadoPortao('', false);
    iniciarChuva(el.rain);
    // se este aparelho já passou pelo portão, tenta reentrar direto
    const salvo = lerLS(LS_PLAYER);
    if (salvo.portao) {
      estadoPortao('reconectando...', false);
      try {
        const cfg = await buscarConfig();
        if (cfg && cfg.gate && (await decifrar(salvo.portao, cfg.gate)) === MARCA_PORTAO) { estadoPortao('', false); entrarNoTerminal(cfg); return; }
        delete salvo.portao; delete salvo.achados; gravarLS(LS_PLAYER, salvo);
      } catch (e) { /* sem rede: cai para o portão */ }
      estadoPortao('', false);
    }
    setTimeout(() => el.gateInput.focus(), 50);
  }

  function fecharEnigma() {
    if (!montado) return;
    ficha++; clearTimeout(timerSussurro);
    el.overlay.hidden = true; document.body.style.overflow = '';
    pararChuva();
    el.log.textContent = ''; el.data.textContent = ''; achados = {};
    if (focoAnterior && focoAnterior.focus) focoAnterior.focus();
  }

  /* ---------- painel do admin ---------- */
  function montarAdmin() {
    if (document.getElementById('en-admin')) return;
    const m = document.createElement('div');
    m.id = 'en-admin';
    m.className = 'fixed inset-0 bg-black/80 flex items-center justify-center z-[3500] hidden';
    const campo = 'w-full bg-black border border-gray-600 rounded p-2 text-white text-sm focus:border-green-500 focus:outline-none';
    m.innerHTML =
      '<div class="bg-gray-900 border border-gray-700 p-5 rounded-lg shadow-2xl max-w-lg mx-4 w-full max-h-[90vh] overflow-y-auto">' +
        '<h3 class="text-lg text-green-400 mb-1 font-bold text-center">☠ CONFIGURAR ENIGMA</h3>' +
        '<p class="text-[11px] text-gray-500 mb-3 text-center">As mesmas senhas valem para os dois times. Tudo é gravado cifrado no Firebase.</p>' +
        '<div class="space-y-3">' +
          '<div><label class="block text-xs text-green-400 mb-1">1) Senha da caveira (portão)</label><input id="en-a-gate" type="text" autocomplete="off" class="' + campo + '"></div>' +
          '<div><label class="block text-xs text-gray-400 mb-1">Mensagem exibida no terminal (pista / texto cifrado - opcional)</label><textarea id="en-a-msg" rows="3" class="' + campo + '"></textarea></div>' +
          '<div class="border-t border-gray-700 pt-3"><label class="block text-xs text-green-400 mb-1">2) Senha de decifração (revela o local da nave)</label><input id="en-a-s2" type="text" autocomplete="off" class="' + campo + '"></div>' +
          '<div><label class="block text-xs text-gray-400 mb-1">Coordenadas / local da nave (ex: -17.763466, -48.649717)</label><textarea id="en-a-coord" rows="2" class="' + campo + '"></textarea></div>' +
          '<div class="border-t border-gray-700 pt-3"><label class="block text-xs text-green-400 mb-1">3) Senha da nave (revela as áreas do alienígena)</label><input id="en-a-s3" type="text" autocomplete="off" class="' + campo + '"></div>' +
          '<div><label class="block text-xs text-gray-400 mb-1">Áreas possíveis do alienígena</label><textarea id="en-a-areas" rows="3" class="' + campo + '"></textarea></div>' +
        '</div>' +
        '<p id="en-a-status" class="text-xs mt-3 min-h-[16px] text-center text-gray-400"></p>' +
        '<div class="flex flex-wrap justify-between gap-2 mt-2">' +
          '<button type="button" id="en-a-off" class="px-3 py-2 bg-red-950 hover:bg-red-900 text-red-300 rounded text-xs border border-red-800">DESATIVAR</button>' +
          '<div class="flex gap-2"><button type="button" id="en-a-cancel" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded font-bold border border-gray-600">CANCELAR</button>' +
          '<button type="button" id="en-a-save" class="px-4 py-2 bg-green-900 hover:bg-green-800 text-white rounded font-bold border border-green-600">SALVAR</button></div>' +
        '</div>' +
      '</div>';
    document.body.appendChild(m);
    m.querySelector('#en-a-cancel').addEventListener('click', fecharAdmin);
    m.querySelector('#en-a-save').addEventListener('click', salvarAdmin);
    m.querySelector('#en-a-off').addEventListener('click', desativarAdmin);
  }
  const $a = (id) => document.getElementById(id);
  function statusAdmin(t, cor) { const s = $a('en-a-status'); s.textContent = t; s.className = 'text-xs mt-3 min-h-[16px] text-center ' + (cor || 'text-gray-400'); }

  function abrirEnigmaAdmin() {
    if (typeof isAdmin === 'undefined' || !isAdmin) return;
    montarAdmin();
    const c = lerLS(LS_ADMIN);
    $a('en-a-gate').value = c.gate || ''; $a('en-a-msg').value = c.msg || '';
    $a('en-a-s2').value = c.s2 || ''; $a('en-a-coord').value = c.coord || '';
    $a('en-a-s3').value = c.s3 || ''; $a('en-a-areas').value = c.areas || '';
    statusAdmin(c.gate ? 'Valores desta máquina carregados. O Firebase guarda só a versão cifrada.' : 'Ainda não configurado neste aparelho.', 'text-gray-500');
    $a('en-admin').classList.remove('hidden');
  }
  function fecharAdmin() { const m = $a('en-admin'); if (m) m.classList.add('hidden'); }

  async function salvarAdmin() {
    const v = { gate: $a('en-a-gate').value, msg: $a('en-a-msg').value.trim(), s2: $a('en-a-s2').value, coord: $a('en-a-coord').value.trim(), s3: $a('en-a-s3').value, areas: $a('en-a-areas').value.trim() };
    if (!norm(v.gate) || !norm(v.s2) || !norm(v.s3)) { statusAdmin('Preencha as três senhas.', 'text-red-400'); return; }
    if (!v.coord || !v.areas) { statusAdmin('Preencha as coordenadas e as áreas do alienígena.', 'text-red-400'); return; }
    if (new Set([norm(v.gate), norm(v.s2), norm(v.s3)]).size < 3) { statusAdmin('As três senhas precisam ser diferentes entre si.', 'text-red-400'); return; }
    const btn = $a('en-a-save'); btn.disabled = true; statusAdmin('cifrando e salvando...', 'text-gray-400');
    try {
      const [gate, coord, areas] = await Promise.all([cifrar(v.gate, MARCA_PORTAO), cifrar(v.s2, v.coord), cifrar(v.s3, v.areas)]);
      const corpo = { gate, coord, areas, ts: Date.now() };
      if (v.msg) corpo.msg = v.msg;
      const res = await fetch(CFG_URL, { method: 'PUT', body: JSON.stringify(corpo) });
      if (!res.ok) throw new Error('http ' + res.status);
      gravarLS(LS_ADMIN, v);
      statusAdmin('Enigma salvo. Jogadores que já tinham acesso precisarão da nova senha se você a trocou.', 'text-green-400');
      if (typeof mostrarToast === 'function') mostrarToast('Enigma salvo');
    } catch (e) { statusAdmin('Falha ao salvar no Firebase. Tente de novo.', 'text-red-400'); }
    finally { btn.disabled = false; }
  }

  async function desativarAdmin() {
    if (!confirm('Desativar o enigma? A caveira deixará de funcionar até você configurar de novo.')) return;
    try {
      const res = await fetch(CFG_URL, { method: 'DELETE' });
      if (!res.ok) throw new Error('http ' + res.status);
      statusAdmin('Enigma desativado.', 'text-yellow-400');
    } catch (e) { statusAdmin('Falha ao desativar.', 'text-red-400'); }
  }

  window.abrirEnigma = abrirEnigma;
  window.abrirEnigmaAdmin = abrirEnigmaAdmin;
})();
