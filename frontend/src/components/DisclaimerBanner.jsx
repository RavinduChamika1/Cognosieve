import React from 'react';
import { AlertTriangle } from 'lucide-react';

export default function DisclaimerBanner() {
  return (
    <div className="disclaimer-banner">
      <AlertTriangle size={18} style={{ flexShrink: 0 }} />
      <span>
        <strong>Authorized Security Testing Only:</strong> You must own the target domain or hold explicit written permission from the owner. Scanning unauthorized systems violates cybercrime statutes. Out-of-scope rules strictly override in-scope rules.
      </span>
    </div>
  );
}
