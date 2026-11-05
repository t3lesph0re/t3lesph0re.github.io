/**
 * code-enhance.js
 * CLI blocks: prompt highlighting + copy (commands only).
 * Code blocks: GitHub style with line numbers + copy (whole block).
 * Works with: .highlighter-rouge > .highlight > pre > code
 * No dependencies.
 */
(function () {
  'use strict';

  var WIN_PROMPT = /^((?:PS )?[A-Z]:\\[^>]*>\s?)(.*)$/;
  var NIX_PROMPT = /^(\s*[\w.-]+@[\w.-]+:\S*[$#]\s|[$#]\s)(.*)$/;
  var CLI_LANGS = /^(text|plaintext|bash|shell|console|powershell|ps1|batch|cmd)$/i;

  function extractCommands(text) {
    var cmds = [];
    text.split('\n').forEach(function (l) {
      var w = l.match(WIN_PROMPT);
      var n = l.match(NIX_PROMPT);
      if (w) cmds.push(w[2]);
      else if (n) cmds.push(n[2]);
    });
    return cmds.length ? cmds.join('\n') : text;
  }

  function enhanceBlock(container) {
    var pre  = container.querySelector('pre');
    var code = container.querySelector('code');
    var raw  = code || pre;
    if (!raw) return;

    var text = raw.textContent;

    // --- Code languages get the GitHub look; everything else stays CLI ---
    var lang = container.className.match(/(?:^|\s)language-([\w+-]+)/);
    var isCode = !!(pre && code && lang && !CLI_LANGS.test(lang[1]));

    if (isCode) {
      var count = text.replace(/\n$/, '').split('\n').length;
      var nums = [];
      for (var n = 1; n <= count; n++) nums.push(n);
      var gutter = document.createElement('span');
      gutter.className = 'code-lines';
      gutter.setAttribute('aria-hidden', 'true');
      gutter.textContent = nums.join('\n');
      container.classList.add('code-block');
      pre.insertBefore(gutter, code);
    }

    // Make the Rouge wrapper the positioning anchor
    container.style.position = 'relative';

    // --- Copy button (appended to .highlighter-rouge) ---
    var btn = document.createElement('button');
    btn.className = 'code-copy';
    btn.setAttribute('aria-label', 'Copy to clipboard');
    btn.innerHTML =
      '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
        '<rect x="9" y="9" width="13" height="13" rx="2"/>' +
        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' +
      '</svg>';

    btn.addEventListener('click', function () {
      var copyText = isCode ? text : extractCommands(text);
      navigator.clipboard.writeText(copyText).then(function () {
        btn.classList.add('copied');
        btn.innerHTML =
          '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
            '<polyline points="20 6 9 17 4 12"/>' +
          '</svg>';
        setTimeout(function () {
          btn.classList.remove('copied');
          btn.innerHTML =
            '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
              '<rect x="9" y="9" width="13" height="13" rx="2"/>' +
              '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' +
            '</svg>';
        }, 1500);
      });
    });

    container.appendChild(btn);

    // --- Prompt highlighting (CLI blocks only) ---
    if (isCode) return;

    var lines = text.split('\n');
    var hasPrompt = lines.some(function (l) {
      return WIN_PROMPT.test(l) || NIX_PROMPT.test(l);
    });

    if (!hasPrompt) return;

    var frag = document.createDocumentFragment();

    lines.forEach(function (line, i) {
      var winMatch = line.match(WIN_PROMPT);
      var nixMatch = line.match(NIX_PROMPT);

      if (winMatch) {
        var ps = document.createElement('span');
        ps.className = 'cli-prompt';
        ps.textContent = winMatch[1];
        var cs = document.createElement('span');
        cs.className = 'cli-cmd';
        cs.textContent = winMatch[2];
        frag.appendChild(ps);
        frag.appendChild(cs);
      } else if (nixMatch) {
        var ps2 = document.createElement('span');
        ps2.className = 'cli-prompt';
        ps2.textContent = nixMatch[1];
        var cs2 = document.createElement('span');
        cs2.className = 'cli-cmd';
        cs2.textContent = nixMatch[2];
        frag.appendChild(ps2);
        frag.appendChild(cs2);
      } else {
        var out = document.createElement('span');
        out.className = 'cli-output';
        out.textContent = line;
        frag.appendChild(out);
      }

      if (i < lines.length - 1) {
        frag.appendChild(document.createTextNode('\n'));
      }
    });

    raw.textContent = '';
    raw.appendChild(frag);
  }

  function init() {
    var rougeBlocks = document.querySelectorAll('.highlighter-rouge');

    if (rougeBlocks.length) {
      for (var i = 0; i < rougeBlocks.length; i++) {
        enhanceBlock(rougeBlocks[i]);
      }
    } else {
      // Fallback: plain <pre> without Rouge
      var pres = document.querySelectorAll('pre');
      for (var j = 0; j < pres.length; j++) {
        var wrapper = document.createElement('div');
        wrapper.className = 'highlighter-rouge';
        pres[j].parentNode.insertBefore(wrapper, pres[j]);
        wrapper.appendChild(pres[j]);
        enhanceBlock(wrapper);
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();