import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuthScope | AI Security Testing Agent",
  description: "Authorized, hard-scoped AI-powered penetration testing agent for web applications and APIs.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark h-full">
      <body className="h-full bg-[#0B0F17] text-[#F9FAFB] flex flex-col selection:bg-blue-600 selection:text-white">
        {children}
      </body>
    </html>
  );
}
