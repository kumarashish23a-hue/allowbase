import { Developers } from '../sections/Developers';
import { Faq } from '../sections/Faq';
import { FinalCta } from '../sections/FinalCta';
import { Hero } from '../sections/Hero';
import { HowItWorks } from '../sections/HowItWorks';
import { TrustPrinciples } from '../sections/TrustPrinciples';
import { Platform } from '../sections/Platform';
import { Pricing } from '../sections/Pricing';
import { Problem } from '../sections/Problem';
import { Security } from '../sections/Security';
import { UseCases } from '../sections/UseCases';

interface HomeProps {
  onDemo: () => void;
}

/** Marketing landing page. The live product lives at /app. */
export function Home({ onDemo }: HomeProps) {
  return (
    <>
      <Hero />
      <Problem />
      <HowItWorks />
      <TrustPrinciples />
      <Platform />
      <Developers />
      <UseCases />
      <Security />
      <Pricing onDemo={onDemo} />
      <Faq />
      <FinalCta onDemo={onDemo} />
    </>
  );
}
