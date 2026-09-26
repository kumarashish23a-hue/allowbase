import { lazy, Suspense, useState } from 'react';
import { Navbar } from './components/Navbar';
import { Agents } from './sections/Agents';
import { AIRequest } from './sections/AIRequest';
import { Approvals } from './sections/Approvals';
import { ApiKeys } from './sections/ApiKeys';
import { DataSources } from './sections/DataSources';
import { Developers } from './sections/Developers';
import { Faq } from './sections/Faq';
import { FinalCta } from './sections/FinalCta';
import { Footer } from './sections/Footer';
import { Hero } from './sections/Hero';
import { HowItWorks } from './sections/HowItWorks';
import { TrustPrinciples } from './sections/TrustPrinciples';
import { Platform } from './sections/Platform';
import { Requests } from './sections/Requests';
import { PolicyEngine } from './sections/PolicyEngine';
import { Pricing } from './sections/Pricing';
import { Problem } from './sections/Problem';
import { Security } from './sections/Security';
import { UseCases } from './sections/UseCases';
import { getActiveOrganization } from './services/organizationService';
import { getSetupStatus } from './services/setupService';
import { ThemeProvider } from './theme';

// Modals are code-split: they load on demand instead of bloating the first paint.
const ProfileModal = lazy(() => import('./components/ProfileModal').then((m) => ({ default: m.ProfileModal })));
const RequestSimulator = lazy(() =>
  import('./components/RequestSimulator').then((m) => ({ default: m.RequestSimulator })),
);
const SetupModal = lazy(() => import('./components/SetupModal').then((m) => ({ default: m.SetupModal })));
const SignInModal = lazy(() => import('./components/SignInModal').then((m) => ({ default: m.SignInModal })));

function App() {
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [signInOpen, setSignInOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [setupOpen, setSetupOpen] = useState(false);

  const openSimulator = () => setSimulatorOpen(true);

  /**
   * After sign-in/sign-up: open the workspace setup checklist when anything
   * is still incomplete (no org, no data, evaluator not deployed).
   * Fully-set-up users land straight back on the page.
   */
  const handleAuthSuccess = async () => {
    setSignInOpen(false);
    try {
      // Fast path: no org yet -> setup modal will handle org creation.
      const org = await getActiveOrganization().catch(() => null);
      if (!org) {
        setSetupOpen(true);
        return;
      }
      const status = await getSetupStatus().catch(() => null);
      if (status && (!status.hasData || status.edgeFunction !== 'deployed')) {
        setSetupOpen(true);
      }
    } catch {
      setSetupOpen(true);
    }
  };

  return (
    <ThemeProvider>
      <div className="min-h-screen">
      <a
        href="#platform"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:bg-accent-500 focus:px-4 focus:py-2 focus:text-sm focus:text-accent-ink"
      >
        Skip to content
      </a>
      <Navbar onSignIn={() => setSignInOpen(true)} onProfile={() => setProfileOpen(true)} />
      <main>
        <Hero />
        <Problem />
        <HowItWorks />
        <TrustPrinciples />
        <Platform />
        <AIRequest onSimulate={openSimulator} />
        <PolicyEngine />
        <Approvals />
        <Agents />
        <DataSources />
        <Security />
        <Developers />
        <ApiKeys />
        <Requests />
        <UseCases />
        <Pricing onDemo={openSimulator} />
        <Faq />
        <FinalCta onDemo={openSimulator} />
      </main>
      <Footer />
      <Suspense fallback={null}>
        <RequestSimulator open={simulatorOpen} onClose={() => setSimulatorOpen(false)} />
        <SignInModal open={signInOpen} onClose={() => setSignInOpen(false)} onAuthSuccess={() => void handleAuthSuccess()} />
        <ProfileModal open={profileOpen} onClose={() => setProfileOpen(false)} onOpenSetup={() => setSetupOpen(true)} />
        <SetupModal
          open={setupOpen}
          onClose={() => setSetupOpen(false)}
          onSignIn={() => setSignInOpen(true)}
          onTrySimulator={openSimulator}
        />
      </Suspense>
      </div>
    </ThemeProvider>
  );
}

export default App;
