import { useState } from 'react';
import { Navbar } from './components/Navbar';
import { RequestSimulator } from './components/RequestSimulator';
import { SignInModal } from './components/SignInModal';
import { Agents } from './sections/Agents';
import { AIRequest } from './sections/AIRequest';
import { DataSources } from './sections/DataSources';
import { Developers } from './sections/Developers';
import { Faq } from './sections/Faq';
import { FinalCta } from './sections/FinalCta';
import { Footer } from './sections/Footer';
import { Hero } from './sections/Hero';
import { HowItWorks } from './sections/HowItWorks';
import { Platform } from './sections/Platform';
import { PolicyEngine } from './sections/PolicyEngine';
import { Pricing } from './sections/Pricing';
import { Problem } from './sections/Problem';
import { Security } from './sections/Security';
import { UseCases } from './sections/UseCases';

function App() {
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [signInOpen, setSignInOpen] = useState(false);

  const openSimulator = () => setSimulatorOpen(true);

  return (
    <div className="min-h-screen">
      <a
        href="#platform"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:bg-accent-500 focus:px-4 focus:py-2 focus:text-sm focus:text-white"
      >
        Skip to content
      </a>
      <Navbar onSignIn={() => setSignInOpen(true)} />
      <main>
        <Hero />
        <Problem />
        <HowItWorks />
        <Platform />
        <AIRequest onSimulate={openSimulator} />
        <PolicyEngine />
        <Agents />
        <DataSources />
        <Security />
        <Developers />
        <UseCases />
        <Pricing onDemo={openSimulator} />
        <Faq />
        <FinalCta onDemo={openSimulator} />
      </main>
      <Footer />
      <RequestSimulator open={simulatorOpen} onClose={() => setSimulatorOpen(false)} />
      <SignInModal open={signInOpen} onClose={() => setSignInOpen(false)} />
    </div>
  );
}

export default App;
