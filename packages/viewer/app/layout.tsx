import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const sans = Inter({
  subsets: ['latin'],
  variable: '--font-sans',
  display: 'swap',
});

const mono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

export const viewport: Viewport = {
  themeColor: '#0a1018',
  colorScheme: 'dark',
  width: 'device-width',
  initialScale: 1,
};

export const metadata: Metadata = {
  title: 'agentgg · scan report',
  description: 'Local report viewer for agentgg scan results.',
  robots: { index: false, follow: false },
  icons: {
    icon: [
      { url: '/favicon-32.png', sizes: '32x32', type: 'image/png' },
      { url: '/favicon-64.png', sizes: '64x64', type: 'image/png' },
    ],
    shortcut: '/favicon-32.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="min-h-screen antialiased bg-bg text-ink font-sans">
        {/* ambient backdrop — lifted from the landing-page hero */}
        <div className="pointer-events-none fixed inset-0 -z-10">
          <div className="absolute inset-0 bg-grid bg-[size:48px_48px] opacity-40" />
          <div className="absolute inset-0 bg-radial-glow" />
          <div className="absolute inset-x-0 top-0 h-[600px] bg-gradient-to-b from-bg-raised to-transparent" />
        </div>
        {children}
      </body>
    </html>
  );
}
