import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import ArchitecturePillars from './components/ArchitecturePillars';
import SimulationSandbox from './components/SimulationSandbox';
import DownloadPortal from './components/DownloadPortal';
import DeliverablesHub from './components/DeliverablesHub';
import AuthModal from './components/AuthModal';
import Footer from './components/Footer';
import GDGMouseCanvas from './components/GDGMouseCanvas';
import CliHeroPage from './components/CliHeroPage';
import CliDocsPage from './components/CliDocsPage';

export default function App() {
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState('home'); // 'home' | 'cli-hero' | 'cli-docs'

  const scrollToSection = (id) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  const handleNavigatePage = (pageId) => {
    setCurrentPage(pageId);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (currentPage === 'cli-hero') {
    return (
      <CliHeroPage
        onNavigateToDocs={() => handleNavigatePage('cli-docs')}
        onNavigateHome={() => handleNavigatePage('home')}
      />
    );
  }

  if (currentPage === 'cli-docs') {
    return (
      <CliDocsPage
        onNavigateToHero={() => handleNavigatePage('cli-hero')}
        onNavigateHome={() => handleNavigatePage('home')}
      />
    );
  }

  return (
    <div className="min-h-screen bg-[#ffffff] text-slate-900 font-sans selection:bg-brand-500 selection:text-white relative overflow-x-hidden">
      
      {/* 🔮 GDG Interactive Mouse Cursor & Touch Ripple Canvas */}
      <GDGMouseCanvas />

      {/* 🎨 GDG / Google Dev Style Interactive Background Canvas */}
      <div className="fixed inset-0 bg-gdg-grid mask-radial-viewport opacity-70 pointer-events-none z-0" />

      {/* 🔮 Floating Ambient Gradient Glow Orbs (Light Mode) */}
      <div className="fixed top-[-10%] right-[-5%] w-[500px] h-[500px] bg-gradient-to-tr from-blue-400/25 to-indigo-400/25 rounded-full blur-[120px] pointer-events-none z-0 animate-float-slow" />
      <div className="fixed top-[35%] left-[-10%] w-[550px] h-[550px] bg-gradient-to-tr from-emerald-400/20 to-teal-300/20 rounded-full blur-[130px] pointer-events-none z-0 animate-float-slow delay-200" />
      <div className="fixed top-[70%] right-[-8%] w-[520px] h-[520px] bg-gradient-to-tr from-amber-400/20 to-rose-300/20 rounded-full blur-[125px] pointer-events-none z-0 animate-float-slow delay-400" />

      {/* Sticky Blurred Navbar */}
      <Navbar
        currentPage={currentPage}
        onNavigateToPage={handleNavigatePage}
        onOpenAuthModal={() => setAuthModalOpen(true)}
        onScrollToSection={scrollToSection}
      />

      {/* Main Content Sections */}
      <main className="relative z-10">
        {/* Section 1: Hero & Network Topology Visualizer */}
        <Hero
          onScrollToSection={scrollToSection}
          onOpenAuthModal={() => setAuthModalOpen(true)}
        />

        {/* Section 2: Core Architectural Pillars */}
        <ArchitecturePillars />

        {/* Section 3: Live Simulation & Demonstration Sandbox */}
        <SimulationSandbox />

        {/* Section 4: Software Download & Deployment Portal */}
        <DownloadPortal
          onOpenAuthModal={() => setAuthModalOpen(true)}
        />

        {/* Section 5: Deliverables & Empirical Benchmarks Hub */}
        <DeliverablesHub />
      </main>

      {/* Footer */}
      <Footer
        onScrollToSection={scrollToSection}
        onOpenAuthModal={() => setAuthModalOpen(true)}
      />

      {/* Auth & Access Key Generator Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
      />
    </div>
  );
}
