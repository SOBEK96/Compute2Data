import type { Metadata } from "next";
import "@fontsource-variable/jetbrains-mono";
import "@fontsource-variable/manrope";

import { AppShell } from "@/components/app-shell";
import { WalletProvider } from "@/components/wallet-provider";

import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "Compute2Data | Private data, verifiable compute",
    template: "%s | Compute2Data",
  },
  description:
    "A collateralized marketplace for verifiable AI compute over private datasets on GenLayer.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <WalletProvider>
          <AppShell>{children}</AppShell>
        </WalletProvider>
      </body>
    </html>
  );
}
