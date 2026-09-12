import React, { useEffect, useState, useRef } from 'react';

export default function GDGMouseCanvas() {
  const [ripples, setRipples] = useState([]);
  const mousePos = useRef({ x: -500, y: -500 });
  const spotlightRef = useRef(null);

  useEffect(() => {
    let animFrame;

    const handleMouseMove = (e) => {
      mousePos.current = { x: e.clientX, y: e.clientY };
    };

    const handleTouchMove = (e) => {
      if (e.touches && e.touches[0]) {
        mousePos.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };
      }
    };

    const updateSpotlight = () => {
      if (spotlightRef.current) {
        spotlightRef.current.style.transform = `translate3d(${mousePos.current.x - 250}px, ${mousePos.current.y - 250}px, 0)`;
      }
      animFrame = requestAnimationFrame(updateSpotlight);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('touchmove', handleTouchMove);
    animFrame = requestAnimationFrame(updateSpotlight);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('touchmove', handleTouchMove);
      cancelAnimationFrame(animFrame);
    };
  }, []);

  const handlePointerDown = (e) => {
    const id = Date.now() + Math.random();
    const colors = ['rgba(59, 130, 246, 0.35)', 'rgba(16, 185, 129, 0.35)', 'rgba(245, 158, 11, 0.35)'];
    const randomColor = colors[Math.floor(Math.random() * colors.length)];

    setRipples((prev) => [
      ...prev.slice(-8), // Keep max 8 active ripples for performance
      { id, x: e.clientX, y: e.clientY, color: randomColor }
    ]);

    setTimeout(() => {
      setRipples((prev) => prev.filter((r) => r.id !== id));
    }, 800);
  };

  useEffect(() => {
    window.addEventListener('pointerdown', handlePointerDown);
    return () => window.removeEventListener('pointerdown', handlePointerDown);
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-30 overflow-hidden">
      {/* 🌟 Interactive Follow-Cursor Radial Spotlight */}
      <div
        ref={spotlightRef}
        className="w-[500px] h-[500px] rounded-full bg-radial-gradient-spotlight opacity-70 transition-opacity duration-500 will-change-transform"
        style={{
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.12) 0%, rgba(99, 102, 241, 0.05) 45%, transparent 70%)',
        }}
      />

      {/* 💧 Animated Touch / Click Ripples */}
      {ripples.map((ripple) => (
        <span
          key={ripple.id}
          className="absolute rounded-full pointer-events-none animate-ripple"
          style={{
            left: `${ripple.x}px`,
            top: `${ripple.y}px`,
            width: '20px',
            height: '20px',
            marginLeft: '-10px',
            marginTop: '-10px',
            boxShadow: `0 0 25px 8px ${ripple.color}`,
            border: `2px solid ${ripple.color}`,
          }}
        />
      ))}
    </div>
  );
}
