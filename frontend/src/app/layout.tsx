import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuthScope | AI Security Testing Agent",
  description: "Authorized, hard-scoped AI-powered penetration testing agent for web applications and APIs.",
  applicationName: "AuthScope",
};

export const viewport: Viewport = {
  themeColor: "#262624",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark h-full">
      <body className="h-full bg-[#262624] text-[#f4f2ec] flex flex-col selection:bg-[#5fa37f]/30 selection:text-[#f4f2ec]">
        {children}
      </body>
    </html>
  );
}
