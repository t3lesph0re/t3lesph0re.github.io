/**
 * code-enhance.js
 * Prompt highlighting + copy button for CLI code blocks.
 * Drop in your Jekyll layout. No dependencies.
 */
(function () {
  'use strict';

  // --- Prompt detection ---
  // Windows CMD:  C:\Users\foo>command
  // Linux root:   # command
  // Linux user:   $ command
  var WIN_PROMPT = /^([A-Z]:\\[^>]*>)(.*)$/;
  var NIX_PROMPT = /^(\$|#)\s(.*)$/;

  function enhanceBlock(pre) {
    var code = pre.querySelector('code');
    var raw  = code || pre;
    var text = raw.textContent;

    // --- Copy button ---
    var btn = document.createElement('button');
    btn.className = 'code-copy';
    btn.setAttribute('aria-label', 'Copy to clipboard');
    btn.innerHTML =
      '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
        '<rect x="9" y="9" width="13" height="13" rx="2"/>' +
        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' +
      '</svg>';

    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(text).then(function () {
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

    // Wrap pre in a relative container for button positioning
    var wrapper = document.createElement('div');
    wrapper.className = 'code-block';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);
    wrapper.appendChild(btn);

    // --- Prompt highlighting ---
    var lines = text.split('\n');
    var hasPrompt = lines.some(function (l) {
      return WIN_PROMPT.test(l) || NIX_PROMPT.test(l);
    });

    if (!hasPrompt) return; // Leave non-CLI blocks alone

    var frag = document.createDocumentFragment();

    lines.forEach(function (line, i) {
      var winMatch = line.match(WIN_PROMPT);
      var nixMatch = line.match(NIX_PROMPT);

      if (winMatch) {
        var promptSpan = document.createElement('span');
        promptSpan.className = 'cli-prompt';
        promptSpan.textContent = winMatch[1];

        var cmdSpan = document.createElement('span');
        cmdSpan.className = 'cli-cmd';
        cmdSpan.textContent = winMatch[2];

        frag.appendChild(promptSpan);
        frag.appendChild(cmdSpan);
      } else if (nixMatch) {
        var ps = document.createElement('span');
        ps.className = 'cli-prompt';
        ps.textContent = nixMatch[1] + ' ';

        var cs = document.createElement('span');
        cs.className = 'cli-cmd';
        cs.textContent = nixMatch[2];

        frag.appendChild(ps);
        frag.appendChild(cs);
      } else {
        var outputSpan = document.createElement('span');
        outputSpan.className = 'cli-output';
        outputSpan.textContent = line;
        frag.appendChild(outputSpan);
      }

      if (i < lines.length - 1) {
        frag.appendChild(document.createTextNode('\n'));
      }
    });

    raw.textContent = '';
    raw.appendChild(frag);
  }

  // --- Init on DOM ready ---
  function init() {
    var blocks = document.querySelectorAll('pre');
    for (var i = 0; i < blocks.length; i++) {
      enhanceBlock(blocks[i]);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
