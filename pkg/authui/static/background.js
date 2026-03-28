(function () {
  const canvas = document.getElementById('auth-bg');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const MOBILE = window.innerWidth < 768;
  const COUNT = MOBILE ? 70 : 160;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function mkStar() {
    return {
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      r: Math.random() * 1.2 + 0.2,
      baseOpacity: Math.random() * 0.55 + 0.15,
      twinkleSpeed: Math.random() * 0.025 + 0.004,
      twinkleOffset: Math.random() * Math.PI * 2,
      dx: (Math.random() - 0.5) * 0.06,
      dy: (Math.random() - 0.5) * 0.06,
    };
  }

  resize();
  const stars = Array.from({ length: COUNT }, mkStar);
  let t = 0;
  let raf;
  let shooter = null;
  let shooterTimeout;

  function spawnShooter() {
    const angle = Math.PI / 4 + (Math.random() - 0.5) * 0.4;
    shooter = {
      x: Math.random() * canvas.width * 0.7,
      y: Math.random() * canvas.height * 0.4,
      angle, speed: 5 + Math.random() * 3,
      length: 180 + Math.random() * 80,
      life: 0, maxLife: 120 + Math.random() * 30,
    };
    shooterTimeout = setTimeout(spawnShooter, 6500 + Math.random() * 2000);
  }

  shooterTimeout = setTimeout(spawnShooter, 3000 + Math.random() * 4000);

  function drawShooter() {
    if (!shooter) return;
    shooter.life++;
    const progress = shooter.life / shooter.maxLife;
    const opacity = progress < 0.15 ? progress / 0.15 : progress > 0.75 ? 1 - (progress - 0.75) / 0.25 : 1;
    shooter.x += Math.cos(shooter.angle) * shooter.speed;
    shooter.y += Math.sin(shooter.angle) * shooter.speed;
    const tailX = shooter.x - Math.cos(shooter.angle) * shooter.length;
    const tailY = shooter.y - Math.sin(shooter.angle) * shooter.length;
    const grad = ctx.createLinearGradient(tailX, tailY, shooter.x, shooter.y);
    grad.addColorStop(0, 'rgba(255,255,255,0)');
    grad.addColorStop(1, `rgba(255,255,255,${opacity * 0.9})`);
    ctx.save();
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1.5;
    ctx.shadowBlur = 6;
    ctx.shadowColor = '#c8d8ff';
    ctx.beginPath();
    ctx.moveTo(tailX, tailY);
    ctx.lineTo(shooter.x, shooter.y);
    ctx.stroke();
    ctx.restore();
    if (shooter.life >= shooter.maxLife) shooter = null;
  }

  function frame() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    t++;
    for (const s of stars) {
      const opacity = s.baseOpacity * (0.55 + 0.45 * Math.sin(t * s.twinkleSpeed + s.twinkleOffset));
      s.x += s.dx; s.y += s.dy;
      if (s.x < 0) s.x = canvas.width; else if (s.x > canvas.width) s.x = 0;
      if (s.y < 0) s.y = canvas.height; else if (s.y > canvas.height) s.y = 0;
      ctx.save();
      ctx.globalAlpha = opacity;
      ctx.shadowBlur = s.r * 8;
      ctx.shadowColor = '#c8d8ff';
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
    drawShooter();
    raf = requestAnimationFrame(frame);
  }

  window.addEventListener('resize', resize);
  raf = requestAnimationFrame(frame);
})();
