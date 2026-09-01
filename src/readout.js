// Header readout: a six-flap split-flap display that settles on a short
// status word, then reshuffles to the next one. Pure canvas, driven only by
// requestAnimationFrame. No timers, no storage, no network.
(function () {
  var cv = document.getElementById('readout');
  if (!cv || !cv.getContext) return;
  var ctx = cv.getContext('2d');

  var WORDS = ['KUNJI ', 'LOCKED', 'SEALED', 'HIDDEN', 'VAULT '];
  var ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ ';
  var N = 6;

  var cells = [];
  for (var i = 0; i < N; i++) cells.push({ shown: WORDS[0][i], target: WORDS[0][i], until: 0 });
  var wi = 0, nextAt = 0, W = 0, H = 0;

  function theme() {
    var s = getComputedStyle(document.documentElement);
    return {
      ink: (s.getPropertyValue('--text') || '#E7E9EA').trim(),
      dim: (s.getPropertyValue('--muted') || '#8B98A5').trim(),
      line: (s.getPropertyValue('--border') || '#2F3336').trim(),
      cell: (s.getPropertyValue('--surface') || '#16181C').trim()
    };
  }
  var COL = theme();

  function fit() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var r = cv.getBoundingClientRect();
    W = Math.max(1, r.width);
    H = Math.max(1, r.height);
    cv.width = Math.round(W * dpr);
    cv.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    COL = theme();
  }

  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function randGlyph() { return ALPHA.charAt((Math.random() * ALPHA.length) | 0); }

  function draw(t) {
    ctx.clearRect(0, 0, W, H);

    if (t > nextAt) {
      nextAt = t + 3.6;
      wi = (wi + 1) % WORDS.length;
      for (var k = 0; k < N; k++) {
        var want = WORDS[wi].charAt(k) || ' ';
        if (want !== cells[k].shown) {
          cells[k].target = want;
          cells[k].until = t + 0.4 + k * 0.14;
        }
      }
    }

    var gap = 3;
    var cw = (W - gap * (N - 1)) / N;
    var fs = Math.max(9, Math.floor(Math.min(cw * 1.25, H * 0.6)));
    ctx.font = '700 ' + fs + 'px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    for (var i = 0; i < N; i++) {
      var x = i * (cw + gap);
      var spinning = t < cells[i].until;
      var glyph = spinning ? randGlyph() : (cells[i].shown = cells[i].target);

      ctx.fillStyle = COL.cell;
      roundRect(x, 0, cw, H, 3);
      ctx.fill();
      ctx.lineWidth = 1;
      ctx.strokeStyle = COL.line;
      roundRect(x + 0.5, 0.5, cw - 1, H - 1, 3);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(x, H / 2);
      ctx.lineTo(x + cw, H / 2);
      ctx.stroke();

      ctx.save();
      ctx.beginPath();
      ctx.rect(x, 0, cw, H);
      ctx.clip();
      ctx.translate(x + cw / 2, H / 2 + 1);
      if (spinning) {
        ctx.scale(1, Math.max(0.08, Math.abs(Math.cos((cells[i].until - t) * 22))));
      }
      ctx.fillStyle = spinning ? COL.dim : COL.ink;
      ctx.fillText(glyph, 0, 0);
      ctx.restore();
    }
  }

  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var startTs = 0;

  function frame(now) {
    if (!startTs) startTs = now;
    draw((now - startTs) / 1000);
    if (!reduce) requestAnimationFrame(frame);
  }

  fit();
  window.addEventListener('resize', fit);

  if (reduce) {
    for (var j = 0; j < N; j++) {
      var c = 'KUNJI '.charAt(j) || ' ';
      cells[j].shown = cells[j].target = c;
      cells[j].until = 0;
    }
    draw(0);
  } else {
    requestAnimationFrame(frame);
  }
})();
