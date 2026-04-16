import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Model Combat",
  description: "A retro arcade cybersecurity benchmark where LLM fighters attack, patch, and survive.",
  icons: {
    icon: "/logo.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
