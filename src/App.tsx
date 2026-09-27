import { lazy, Suspense, useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Footer } from './sections/Footer';
import { Home } from './pages/Home';
import { Console } from './pages/Console';
import { getActiveOrganization } from './services/organizationService';
import { getSetupStatus } from './services/setupService';
import { ThemeProvider } from './theme';

// Modals are code-split: they load on demand instead of bloating the first paint.
const ProfileModal = lazy(() => import('./components/ProfileModal').then((m) => ({ default: m.ProfileModal })));
const RequestSimulator = lazy(() =>
  import('./components/RequestSimulator').then((m) => ({ default: m.RequestSimulator })),
);
const Admin = lazy(() => import('./pages/Admin').then((m) => ({ default: m.Admin })));
const SetupModal = lazy(() => import('./components/SetupModal').then((m) => ({ default: m.SetupModal })));
const SignInModal = lazy(() => import('./components/SignInModal').then((m) => ({ default: m.SignInModal })));

/** Scrolls to top on page change, or to the anchored section for #hash links. */
function ScrollManager() {
  const { pathname, hash } = useLocation();
  useEffect(() => {
    if (hash) {
      const id = hash.replace('#', '');
      // Wait a tick so the new page has rendered.
      const timer = window.setTimeout(() => {
        document.getElementById(id)?.scrollIntoView();
      }, 50);
      return () => window.clearTimeout(timer);
    }
    window.scrollTo(0, 0);
  }, [pathname, hash ]);
  return null;
}

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
      if (
        status &&
        (!status.hasData ||
          status.migrations.state !== 'ok' ||
          status.functions['evaluate-ai-request'] !== 'deployed' ||
          status.functions['ingest-event'] !== 'deployed' ||
          !status.hasApiKey ||
          !status.hasRequests)
      ) {
        setSetupOpen(true);
      }
    } catch {
      setSetupOpen(true);
    }
  };

  return (
    <ThemeProvider>
      <BrowserRouter>
        <ScrollManager />
        <div className="min-h-screen">
          <a
            href="#main"
            className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:bg-accent-500 focus:px-4 focus:py-2 focus:text-sm focus:text-accent-ink"
          >
            Skip to content
          </a>
          <Navbar onSignIn={() => setSignInOpen(true)} onProfile={() => setProfileOpen(true)} />
          <main id="main">
            <Routes>
              <Route path="/" element={<Home onDemo={openSimulator} />} />
              <Route path="/app" element={<Console onSimulate={openSimulator} />} />
              <Route path="/admin" element={<Admin />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
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
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
