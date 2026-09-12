import React, { useState, useEffect } from 'react';
import { Shield, Download, Lock, ChevronRight, Terminal, Menu, X, Sparkles } from 'lucide-react';

export default function Navbar({ onOpenAuthModal, onScrollToSection, currentPage = 'home', onNavigateToPage }) {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('hero');

  const navItems = [
    { label: 'Overview', id: 'hero' },
    { label: 'Architecture', id: 'architecture' },
    { label: 'Live Sandbox', id: 'sandbox' },
    { label: 'Downloads', id: 'downloads' },
    { label: 'Benchmarks', id: 'benchmarks' },
    { label: 'NetGuard CLI', id: 'cli-hero', isPage: true },
  ];

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);

      // Determine active section
      const sections = navItems.map(item => document.getElementById(item.id));
      const scrollPos = window.scrollY + 200;

      for (let i = sections.length - 1; i >= 0; i--) {
        const sec = sections[i];
        if (sec && sec.offsetTop <= scrollPos) {
          setActiveSection(navItems[i].id);
          break;
        }
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleNavClick = (item) => {
    if (typeof item === 'string') {
      const found = navItems.find(i => i.id === item);
      if (found && found.isPage) {
        onNavigateToPage(found.id);
        return;
      }
      if (currentPage !== 'home' && onNavigateToPage) {
        onNavigateToPage('home');
        setTimeout(() => onScrollToSection(item), 100);
      } else {
        setActiveSection(item);
        onScrollToSection(item);
      }
      return;
    }

    if (item.isPage) {
      if (onNavigateToPage) onNavigateToPage(item.id);
    } else {
      if (currentPage !== 'home' && onNavigateToPage) {
        onNavigateToPage('home');
        setTimeout(() => onScrollToSection(item.id), 100);
      } else {
        setActiveSection(item.id);
        onScrollToSection(item.id);
      }
    }
  };

  return (
    <header className={`sticky top-0 left-0 right-0 z-50 transition-all duration-300 ${
      scrolled 
        ? 'bg-white/75 backdrop-blur-lg border-b border-slate-200/60 shadow-subtle py-3' 
        : 'bg-white/90 backdrop-blur-md border-b border-slate-200/40 py-4'
    }`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between">
          
          {/* Left Branding */}
          <div className="flex items-center space-x-3 cursor-pointer group" onClick={() => handleNavClick('hero')}>
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-brand-600 via-brand-500 to-indigoAcc-600 flex items-center justify-center text-white shadow-glow-cobalt transition-all duration-300 group-hover:scale-105">
              <Shield className="w-6 h-6 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-xl tracking-tight text-slate-900 font-sans">
                  NetGuard
                </span>
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-mono font-medium bg-slate-100 text-slate-700 border border-slate-200/80">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5 beacon-dot-emerald"></span>
                  v1.0.4
                </span>
              </div>
              <p className="text-[11px] font-mono text-slate-500 font-medium tracking-tight">
                Enterprise Defense // NTRO PS-26153
              </p>
            </div>
          </div>

          {/* Desktop Navigation Links with Sliding Active Capsule */}
          <nav className="hidden md:flex items-center space-x-1 bg-slate-100/80 p-1.5 rounded-full border border-slate-200/70 backdrop-blur-sm relative">
            {navItems.map((item) => {
              const isActive = item.isPage ? currentPage === item.id : (currentPage === 'home' && activeSection === item.id);
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item)}
                  className={`px-4 py-1.5 text-xs lg:text-sm font-semibold rounded-full transition-all duration-300 relative z-10 ${
                    isActive
                      ? 'text-brand-700 font-bold'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
                  }`}
                >
                  {isActive && (
                    <span className="absolute inset-0 bg-white rounded-full shadow-subtle border border-slate-200/60 -z-10 animate-fade-in" />
                  )}
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Right CTAs */}
          <div className="hidden sm:flex items-center space-x-3">
            <button
              onClick={onOpenAuthModal}
              className="inline-flex items-center space-x-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold text-slate-700 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 transition-all duration-200 active:scale-[0.98]"
            >
              <Lock className="w-3.5 h-3.5 text-slate-500" />
              <span>Portal Sign In</span>
            </button>

            <button
              onClick={() => window.open('https://github.com/MADOUT20/SIH-2026', '_blank')}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-brand-600 via-brand-600 to-indigoAcc-600 hover:from-brand-700 hover:to-indigoAcc-700 shadow-glow-cobalt btn-shimmer transition-all duration-300 hover:-translate-y-0.5 active:scale-[0.98]"
            >
              <Download className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>Download NetGuard</span>
            </button>
          </div>

          {/* Mobile Menu Button */}
          <div className="md:hidden flex items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-xl text-slate-600 hover:bg-slate-100 focus:outline-none"
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>

        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden bg-white/95 backdrop-blur-xl border-b border-slate-200 px-4 pt-3 pb-6 space-y-3 animate-fade-in">
          <div className="flex flex-col space-y-1">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => {
                  handleNavClick(item);
                  setMobileMenuOpen(false);
                }}
                className={`text-left px-3.5 py-2.5 text-sm font-semibold rounded-xl transition-all ${
                  (item.isPage ? currentPage === item.id : (currentPage === 'home' && activeSection === item.id))
                    ? 'bg-brand-50 text-brand-700 font-bold' 
                    : 'text-slate-700 hover:bg-slate-50'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
          <div className="pt-3 border-t border-slate-100 flex flex-col space-y-2">
            <button
              onClick={() => {
                onOpenAuthModal();
                setMobileMenuOpen(false);
              }}
              className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 transition-all active:scale-[0.98]"
            >
              <Lock className="w-4 h-4" />
              <span>Analyst Portal Login</span>
            </button>
            <button
              onClick={() => {
                window.open('https://github.com/MADOUT20/SIH-2026', '_blank');
                setMobileMenuOpen(false);
              }}
              className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl text-sm font-bold text-white bg-brand-600 hover:bg-brand-700 btn-shimmer shadow-glow-cobalt transition-all active:scale-[0.98]"
            >
              <Download className="w-4 h-4" />
              <span>Download NetGuard Client</span>
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
