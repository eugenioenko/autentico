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
    function setRevealed(revealed) {
      input.type = revealed ? 'text' : 'password';
      toggle.setAttribute('aria-label', revealed ? 'Hide password' : 'Show password');
      toggle.setAttribute('aria-pressed', String(revealed));
      toggle.classList.toggle('is-revealed', revealed);
    }
    setRevealed(false);
    toggle.addEventListener('click', function () {
      setRevealed(input.type === 'password');
    });
    // Also mask when restoring a page from the browser's back/forward cache.
    window.addEventListener('pageshow', function (event) {
      if (event.persisted) setRevealed(false);
    });
    wrapper.append(toggle);
  });
})();
