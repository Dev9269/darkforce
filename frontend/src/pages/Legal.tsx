import { Link } from "react-router-dom";
import { ArrowLeft, Shield, ScrollText, Cookie } from "lucide-react";

type LegalDoc = {
  id: string;
  title: string;
  icon: JSX.Element;
  updated: string;
  intro: string;
  sections: { heading: string; body: string }[];
};

const TERMS: LegalDoc = {
  id: "terms",
  title: "TERMS OF SERVICE",
  icon: <ScrollText size={14} />,
  updated: "29 September 2026",
  intro:
    "DarkForce is a research-only threat-intelligence console. By accessing or using this platform you agree to these terms. If you do not agree, do not use the service.",
  sections: [
    {
      heading: "1. Authorised research use",
      body:
        "This console is provided exclusively for lawful security research, academic study, and defensive threat intelligence. You may not use it to engage in, facilitate, or support any criminal, unlawful, or harmful activity, including the purchase of illegal goods or services, fraud, or the targeting of third parties.",
    },
    {
      heading: "2. No warranty",
      body:
        "The data presented — including classifications, findings, severities, and attribution confidence — is analytical output from automated collection and heuristics. It is provided 'as is' with no warranty of accuracy, completeness, or fitness for any purpose. Do not rely on it for operational decisions without independent verification.",
    },
    {
      heading: "3. Acceptable use",
      body:
        "Automated or manual abuse of the console's endpoints, attempts to bypass access controls, scraping beyond the documented API surface, or interference with its operation is prohibited. Probing features, where enabled, are analyst-triggered and must be used only against systems you are authorised to test.",
    },
    {
      heading: "4. Intellectual property",
      body:
        "The software, interface, and documentation are licensed to you on a non-exclusive basis for internal research. You may not resell, sublicense, or republish the service or its data without prior written consent.",
    },
    {
      heading: "5. Termination",
      body:
        "We may suspend or terminate access at any time, with or without notice, for violation of these terms, suspected abuse, or business reasons. Provisions concerning liability, warranty disclaimers, and governing law survive termination.",
    },
    {
      heading: "6. Limitation of liability",
      body:
        "To the maximum extent permitted by law, the operators of DarkForce are not liable for any direct, indirect, incidental, or consequential damages arising from use of the platform, its data, or any decisions made on the basis of its output.",
    },
    {
      heading: "7. Governing law",
      body:
        "These terms are governed by the laws of the jurisdiction in which the operator is established. You are solely responsible for compliance with the laws applicable to you.",
    },
  ],
};

const PRIVACY: LegalDoc = {
  id: "privacy",
  title: "PRIVACY POLICY",
  icon: <Shield size={14} />,
  updated: "29 September 2026",
  intro:
    "This policy explains what personal data DarkForce collects, why it collects it, and the limited purposes for which it is used. We keep collection to the minimum the service needs to operate.",
  sections: [
    {
      heading: "1. Information we collect",
      body:
        "Account credentials (username and a salted, hashed password), audit logs of your own API activity (username, role, route, status, timestamp), and your IP address for rate-limiting and abuse prevention. We do not collect browsing behaviour unrelated to the console.",
    },
    {
      heading: "2. How it is used",
      body:
        "Authentication and authorisation, auditing actions performed on the platform, and enforcing rate limits. Collection and enrichment targets you submit are stored so results can be audited and re-verified; they are not sold or shared with third parties.",
    },
    {
      heading: "3. Cookies and local storage",
      body:
        "The dashboard stores a session token and a small theme preference in your browser's local storage so you stay signed in and keep your chosen appearance. No third-party tracking cookies are used. See the Cookie Policy for details.",
    },
    {
      heading: "4. Data we do not collect",
      body:
        "We do not run analytics trackers, advertising, or social-media buttons, and we do not buy or append personal data from data brokers.",
    },
    {
      heading: "5. Retention",
      body:
        "Collected darknet corpus data is retained while the research programme is active. Account and audit records are retained for as long as the account exists plus a reasonable period to support security review.",
    },
    {
      heading: "6. Your rights",
      body:
        "You may request a copy, correction, or deletion of the personal data we hold about you by contacting the operator. We will respond within the period required by applicable law.",
    },
    {
      heading: "7. Contact",
      body:
        "Questions about this policy can be sent to the platform operator's published contact channel. We will respond as soon as practicable.",
    },
  ],
};

const COOKIES: LegalDoc = {
  id: "cookies",
  title: "COOKIE POLICY",
  icon: <Cookie size={14} />,
  updated: "29 September 2026",
  intro:
    "DarkForce uses only the local browser storage required for the console to function. We do not use advertising, analytics, or cross-site tracking cookies.",
  sections: [
    {
      heading: "1. Session token",
      body:
        "When you sign in, a signed session token is stored in your browser's local storage. It authenticates your API requests and expires automatically. Clearing your storage signs you out.",
    },
    {
      heading: "2. Theme preference",
      body:
        "Your light/dark theme choice is saved locally so the interface stays consistent across visits. It contains no personal or tracking data.",
    },
    {
      heading: "3. What we do not store",
      body:
        "No third-party cookies, fingerprinting, advertising identifiers, or cross-site beacons. This console does not share data with ad networks or analytics providers.",
    },
    {
      heading: "4. Managing storage",
      body:
        "You can clear local storage at any time through your browser's site-data or developer tools settings. Doing so may sign you out and reset the theme preference, but will not affect collected research data on the server.",
    },
  ],
};

const DOCS: Record<string, LegalDoc> = {
  terms: TERMS,
  privacy: PRIVACY,
  cookies: COOKIES,
};

export default function Legal({ docId }: { docId: string }) {
  const doc = DOCS[docId] ?? TERMS;
  return (
    <div className="console-shell legal-shell">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        {Object.values(DOCS).map((d) => (
          <Link key={d.id} to={`/${d.id}`} className={`registry-back ${d.id === doc.id ? "registry-title" : ""}`}>
            {d.icon} {d.title.split(" ")[0]}
          </Link>
        ))}
        <span className="mono registry-total">EFFECTIVE {doc.updated}</span>
      </nav>
      <main className="console-main legal-main">
        <h1 className="legal-h1">{doc.title}</h1>
        <p className="muted-text">{doc.intro}</p>
        {doc.sections.map((s) => (
          <section key={s.heading} className="legal-section">
            <h2 className="legal-h2">{s.heading}</h2>
            <p className="legal-body">{s.body}</p>
          </section>
        ))}
        <p className="legal-footnote mono">
          DARKFORCE // RESEARCH CONSOLE — LEGAL {doc.updated}
        </p>
      </main>
    </div>
  );
}