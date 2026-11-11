(function () {
  const canvas = document.getElementById('canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let particles = [];
  const MOBILE = window.innerWidth < 768;
  const COUNT = MOBILE ? 40 : 100;
  const DISTANCE = MOBILE ? 100 : 150;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function createParticles() {
    particles = [];
    for (let i = 0; i < COUNT; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        r: Math.random() * 2 + 1
      });
    }
  }

  window.addEventListener('resize', () => {
    resize();
    createParticles();
  });

  resize();
  createParticles();

  function frame() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

      ctx.fillStyle = 'rgba(91, 140, 255, 0.4)';
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < DISTANCE) {
          ctx.strokeStyle = `rgba(91, 140, 255, ${0.3 * (1 - dist / DISTANCE)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(frame);
  }
  frame();
})();

// NIST SP 800-63B §5.1.1.2: offer an opt-in display of the entered secret.
// Progressive enhancement keeps ordinary masked inputs usable without JavaScript.
(function () {
  document.querySelectorAll('input.auth-input[type="password"]').forEach(function (input) {
    const wrapper = document.createElement('div');
    wrapper.className = 'auth-password';
    input.before(wrapper);
    wrapper.append(input);

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'auth-password-toggle';
    toggle.setAttribute('aria-controls', input.id);
    const eye = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>';
    const eyeOff = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8M9.9 5.2A11 11 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 3.9M6.1 6.1A18 18 0 0 0 2 12s3.5 7 10 7a12 12 0 0 0 5.9-1.9"/></svg>';
    function setRevealed(revealed) {
      input.type = revealed ? 'text' : 'password';
      toggle.setAttribute('aria-label', revealed ? 'Hide password' : 'Show password');
      toggle.setAttribute('aria-pressed', String(revealed));
      toggle.innerHTML = revealed ? eyeOff : eye;
    }
    setRevealed(false);
    toggle.addEventListener('click', function () {
      setRevealed(input.type === 'password');
    });
    // Also mask when restoring a page from the browser's back/forward cache.
    window.addEventListener('pageshow', function () { setRevealed(false); });
    wrapper.append(toggle);
  });
})();
