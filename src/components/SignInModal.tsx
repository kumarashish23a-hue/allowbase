import { Modal } from './Modal';

interface SignInModalProps {
  open: boolean;
  onClose: () => void;
}

export function SignInModal({ open, onClose }: SignInModalProps) {
  return (
    <Modal open={open} onClose={onClose} title="Sign in" subtitle="Authentication is not implemented in this prototype.">
      <p className="text-sm leading-relaxed text-mist-300">
        This demo focuses on the product experience: discovery, policy, monitoring, and audit. There are no user
        accounts, sessions, or identity providers connected.
      </p>
      <button
        type="button"
        onClick={onClose}
        className="mt-6 w-full rounded-xl bg-accent-500 px-4 py-3 text-sm font-semibold text-white transition hover:bg-accent-400"
      >
        Back to the prototype
      </button>
    </Modal>
  );
}
