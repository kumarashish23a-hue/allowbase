declare module 'vanta/dist/vanta.net.min' {
  interface VantaNetInstance {
    destroy: () => void;
  }
  const NET: (options: Record<string, unknown>) => VantaNetInstance;
  export default NET;
}
