/* copy.js — adds a Copy button to every <pre> code block in the HTML view.
 * Ships with illumio-branded-reports (canonical, hash-checked by
 * check_brand.py). WeasyPrint ignores JavaScript, and .copy-btn is
 * display:none under @media print, so the PDF is never affected.
 */
(function () {
  'use strict';
  if (typeof document === 'undefined') return;

  function extractText(pre) {
    var clone = pre.cloneNode(true);
    var strip = clone.querySelectorAll('.label, .copy-btn');
    for (var i = 0; i < strip.length; i++) {
      strip[i].parentNode.removeChild(strip[i]);
    }
    // strip leading newlines (left behind by the removed label), keep indentation
    return clone.textContent.replace(/^\n+/, '').replace(/\s+$/, '');
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* best effort */ }
    document.body.removeChild(ta);
  }

  function attach(pre) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy code to clipboard');
    btn.addEventListener('click', function () {
      var text = extractText(pre);
      var done = function () {
        btn.textContent = 'Copied ✓';
        btn.classList.add('copied');
        setTimeout(function () {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () {
          fallbackCopy(text);
          done();
        });
      } else {
        fallbackCopy(text);
        done();
      }
    });
    pre.classList.add('has-copy');
    pre.appendChild(btn);
  }

  function init() {
    var pres = document.querySelectorAll('pre');
    for (var i = 0; i < pres.length; i++) attach(pres[i]);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
