import { lazy, Suspense, useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Footer } from './sections/Footer';
import { Home } from './pages/Home';
import { getActiveOrganization } from './services/organizationService';
import { getSetupStatusSafe, setupConnectComplete } from './services/setupService';
import { initForceLogoutWatch } from './lib/forceLogout';
import { ThemeProvider } from './theme';

// Modals are code-split: they load on demand instead of bloating the first paint.
const ProfileModal = lazy(() => import('./components/ProfileModal').then((m) => ({ default: m.ProfileModal })));
const RequestSimulator = lazy(() =>
  import('./components/RequestSimulator').then((m) => ({ default: m.RequestSimulator })),
);
const Admin = lazy(() => import('./pages/Admin').then((m) => ({ default: m.Admin })));
// The console pulls in recharts and every management panel; landing visitors never pay for it.
const Console = lazy(() => import('./pages/Console').then((m) => ({ default: m.Console })));
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

function Shell() {
  const navigate = useNavigate();
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [signInOpen, setSignInOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [setupOpen, setSetupOpen] = useState(false);
  const [setupBlocking, setSetupBlocking] = useState(false);

  // Watch for a workspace admin remotely signing this user out.
  useEffect(() => initForceLogoutWatch(), []);

  const openSimulator = () => setSimulatorOpen(true);

  /**
   * After sign-in/sign-up the flow is: connect everything first, then the
   * dashboard. Incomplete workspaces get the blocking setup wizard; finished
   * ones land straight on the console dashboard.
   */
  const handleAuthSuccess = async () => {
    setSignInOpen(false);
    try {
      // Fast path: no org yet -> setup wizard will handle org creation.
      const org = await getActiveOrganization().catch(() => null);
      if (!org) {
        setSetupBlocking(true);
        setSetupOpen(true);
        return;
      }
      const status = await getSetupStatusSafe().catch(() => null);
      if (!status || !setupConnectComplete(status)) {
        setSetupBlocking(true);
        setSetupOpen(true);
        return;
      }
    } catch {
      setSetupBlocking(true);
      setSetupOpen(true);
      return;
    }
    navigate('/app');
  };

  /** Closing the blocking wizard always lands on the dashboard. */
  const handleSetupClose = () => {
    const wasBlocking = setupBlocking;
    setSetupOpen(false);
    setSetupBlocking(false);
    if (wasBlocking) navigate('/app');
  };

  return (
    <>
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
          <Suspense
            fallback={
              <div className="flex min-h-[60vh] items-center justify-center pt-24">
                <p className="text-sm text-mist-400">Loading…</p>
              </div>
            }
          >
            <Routes>
              <Route path="/" element={<Home onDemo={openSimulator} />} />
              <Route path="/app" element={<Console onSimulate={openSimulator} />} />
              <Route path="/admin" element={<Admin />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </main>
        <Footer />
        <Suspense fallback={null}>
          <RequestSimulator open={simulatorOpen} onClose={() => setSimulatorOpen(false)} />
          <SignInModal open={signInOpen} onClose={() => setSignInOpen(false)} onAuthSuccess={() => void handleAuthSuccess()} />
          <ProfileModal open={profileOpen} onClose={() => setProfileOpen(false)} onOpenSetup={() => setSetupOpen(true)} />
          <SetupModal
            open={setupOpen}
            blocking={setupBlocking}
            onClose={handleSetupClose}
            onSignIn={() => setSignInOpen(true)}
            onTrySimulator={openSimulator}
          />
        </Suspense>
      </div>
    </>
  );
}

function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Shell />
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
